// Copyright (c) 2026 cheig; GPL-3.0.
package com.example.layanalyzer

import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.platform.app.InstrumentationRegistry
import java.io.ByteArrayOutputStream
import java.io.File
import java.nio.ByteBuffer
import java.nio.ByteOrder
import java.util.UUID
import org.json.JSONObject
import org.junit.Assert.*
import org.junit.Before
import org.junit.Test
import org.junit.runner.RunWith

/** R08: tiny synthetic captures, production JNI; no user files or network. */
@RunWith(AndroidJUnit4::class)
class ReleaseLegacyCoreTest {
    @Before fun ready() { NativeTestSupport.awaitApplicationEngine() }

    @Test fun pcapAndPcapngPreservePacketsFilteringStatisticsAndUdpFollow() {
        val payloads = listOf("R08 client payload", "R08 server payload")
        val packets = payloads.mapIndexed { index, payload -> udp(payload.toByteArray(), index == 1) }
        val formats = listOf("pcap" to classic(packets), "pcapng" to nextGeneration(packets))
        val context = InstrumentationRegistry.getInstrumentation().targetContext
        for ((extension, bytes) in formats) {
            val file = File(context.cacheDir, "r08-${UUID.randomUUID()}.$extension")
            file.writeBytes(bytes)
            val handle = NativeEngine.openFile(file.path, null)
            try {
                assertNotEquals(NativeEngine.getLastError(), 0L, handle)
                assertEquals(2, NativeEngine.getFrameCount(handle))
                packets.forEachIndexed { index, packet ->
                    assertArrayEquals(packet, NativeEngine.getPacketBytes(handle, index))
                    assertTrue(NativeEngine.getPacketDetails(handle, index).contains("udp"))
                }
                val statistics = JSONObject(NativeEngine.buildStatistics(handle, 1.0))
                assertEquals(2, statistics.getInt("packetCount"))
                assertEquals(packets.sumOf { it.size }.toLong(), statistics.getLong("byteCount"))
                val follow = JSONObject(NativeEngine.followStream(handle, 0, "udp"))
                assertEquals("udp", follow.getString("protocol"))
                val records = follow.getJSONArray("records")
                assertEquals(2, records.length())
                payloads.forEachIndexed { index, payload ->
                    assertTrue(records.getJSONObject(index).getBoolean("payload"))
                    assertEquals(payload, records.getJSONObject(index).getString("ascii"))
                }
                val filtered = JSONObject(NativeEngine.applyDisplayFilter(handle, "frame.number == 2"))
                assertTrue(filtered.getBoolean("success"))
                assertEquals(1, NativeEngine.getFilteredFrameCount(handle))
                assertEquals(1, JSONObject(NativeEngine.buildStatistics(handle, 1.0)).getInt("packetCount"))
                assertEquals(1, JSONObject(NativeEngine.followStream(handle, 1, "udp")).getJSONArray("records").length())
                assertTrue(JSONObject(NativeEngine.applyDisplayFilter(handle, "")).getBoolean("success"))
                assertEquals(2, NativeEngine.getFilteredFrameCount(handle))
                assertArrayEquals("Analysis must not rewrite the input", bytes, file.readBytes())
            } finally {
                if (handle != 0L) NativeEngine.closeFile(handle)
                file.delete()
            }
        }
    }

    @Test fun tcpFollowRetainsBothDirectionsWithProductionGoldenPackets() {
        TlsPassiveFixture("tls12-h1").use { fixture ->
            val handle = fixture.open()
            try {
                val result = JSONObject(NativeEngine.followStream(handle, 0, "tcp"))
                assertEquals("tcp", result.getString("protocol"))
                assertTrue(result.getBoolean("directionKnown"))
                val records = result.getJSONArray("records")
                val directions = (0 until records.length()).map { records.getJSONObject(it) }
                    .filter { it.getBoolean("payload") && it.getInt("length") > 0 }.map { it.getString("direction") }.toSet()
                assertEquals(setOf("client", "server"), directions)
            } finally { fixture.closeCapture(handle) }
        }
    }

    private fun udp(payload: ByteArray, reverse: Boolean): ByteArray {
        val source = byteArrayOf(192.toByte(), 0, 2, 1)
        val destination = byteArrayOf(198.toByte(), 51, 100, 2)
        val packet = ByteBuffer.allocate(28 + payload.size).order(ByteOrder.BIG_ENDIAN)
            .put(0x45).put(0).putShort((28 + payload.size).toShort()).putInt(0)
            .put(64).put(17).putShort(0).put(if (reverse) destination else source)
            .put(if (reverse) source else destination)
            .putShort((if (reverse) 40001 else 40000).toShort())
            .putShort((if (reverse) 40000 else 40001).toShort())
            .putShort((8 + payload.size).toShort()).putShort(0).put(payload).array()
        var sum = (0 until 20 step 2).sumOf { ((packet[it].toInt() and 255) shl 8) + (packet[it + 1].toInt() and 255) }
        while (sum ushr 16 != 0) sum = (sum and 65535) + (sum ushr 16)
        ByteBuffer.wrap(packet).order(ByteOrder.BIG_ENDIAN).putShort(10, sum.inv().toShort())
        return packet
    }

    private fun buffer(size: Int) = ByteBuffer.allocate(size).order(ByteOrder.LITTLE_ENDIAN)

    private fun classic(packets: List<ByteArray>): ByteArray = ByteArrayOutputStream().apply {
        write(buffer(24).putInt(0xa1b2c3d4.toInt()).putShort(2).putShort(4).putInt(0).putInt(0)
            .putInt(65535).putInt(101).array())
        packets.forEachIndexed { index, packet ->
            write(buffer(16).putInt(1).putInt(index * 1000).putInt(packet.size).putInt(packet.size).array())
            write(packet)
        }
    }.toByteArray()

    private fun nextGeneration(packets: List<ByteArray>): ByteArray = ByteArrayOutputStream().apply {
        write(buffer(28).putInt(0x0a0d0d0a).putInt(28).putInt(0x1a2b3c4d).putShort(1).putShort(0)
            .putLong(-1).putInt(28).array())
        write(buffer(20).putInt(1).putInt(20).putShort(101).putShort(0).putInt(65535).putInt(20).array())
        packets.forEachIndexed { index, packet ->
            val padded = (packet.size + 3) / 4 * 4
            val block = buffer(32 + padded).putInt(6).putInt(32 + padded).putInt(0).putInt(0)
                .putInt(1_000_000 + index * 1000).putInt(packet.size).putInt(packet.size).put(packet)
            block.position(28 + padded)
            write(block.putInt(32 + padded).array())
        }
    }.toByteArray()
}
