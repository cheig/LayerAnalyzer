package com.example.layanalyzer

import android.content.Context
import androidx.test.core.app.ApplicationProvider
import androidx.test.ext.junit.runners.AndroidJUnit4
import org.json.JSONObject
import kotlinx.coroutines.flow.first
import kotlinx.coroutines.runBlocking
import kotlinx.coroutines.withTimeout
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotEquals
import org.junit.Assert.assertTrue
import org.junit.BeforeClass
import org.junit.Test
import org.junit.runner.RunWith
import java.io.File
import java.nio.ByteBuffer
import java.nio.ByteOrder

@RunWith(AndroidJUnit4::class)
class FilteredCaptureExportTest {
    @Test
    fun sipExportIncludesTcpSegmentsInCaptureOrder() {
        val message = sipMessage()
        val packets = tcpHandshake() + listOf(
            ipv4(tcp(message.copyOfRange(0, 64), 101), 6, 4),
            ipv4(udp("unrelated".toByteArray()), 17, 5),
            ipv4(tcp(message.copyOfRange(64, 128), 165), 6, 6),
            ipv4(tcp(message.copyOfRange(128, message.size), 229), 6, 7)
        )
        checkExport(packets, listOf(3, 5, 6), "sip", 1)
    }

    @Test
    fun sipExportIncludesIpv4FragmentsAndExcludesOtherDatagrams() {
        val payload = udp(sipMessage())
        val other = udp(sipMessage("unrelated"))
        val packets = listOf(
            ipv4(payload.copyOfRange(0, 80), 17, 10, 0x2000),
            ipv4(other.copyOfRange(0, 80), 17, 11, 0x2000),
            ipv4(payload.copyOfRange(80, payload.size), 17, 10, 10),
            ipv4(other.copyOfRange(80, other.size), 17, 11, 10)
        )
        checkExport(packets, listOf(0, 2), "sip.Call-ID == \"export-fragments\"", 1)
    }

    @Test
    fun sipExportIncludesIpv6Fragments() {
        val payload = udp(sipMessage())
        checkExport(
            listOf(
                ipv6Fragment(payload.copyOfRange(0, 80), 1),
                ipv6Fragment(payload.copyOfRange(80, payload.size), 80)
            ),
            listOf(0, 1), "sip", 1
        )
    }

    @Test
    fun sipExportIncludesTransitiveIpAndTcpDependencies() {
        val message = sipMessage()
        val firstSegment = tcp(message.copyOfRange(0, 128), 101)
        val packets = tcpHandshake() + listOf(
            ipv4(firstSegment.copyOfRange(0, 80), 6, 20, 0x2000),
            ipv4(firstSegment.copyOfRange(80, firstSegment.size), 6, 20, 10),
            ipv4(tcp(message.copyOfRange(128, message.size), 229), 6, 21)
        )
        checkExport(packets, listOf(3, 4, 5), "sip", 1)
    }

    @Test
    fun repeatedExportsDoNotLeakDependenciesAcrossFilters() {
        val payload = udp(sipMessage())
        val packets = listOf(
            ipv4(payload.copyOfRange(0, 80), 17, 10, 0x2000),
            ipv4(payload.copyOfRange(80, payload.size), 17, 10, 10),
            ipv4(udp("unrelated".toByteArray()), 17, 11)
        )
        checkExport(packets, listOf(0, 1), "sip", 1, subsequentFrame = 3)
    }

    @Test
    fun alreadyVisibleDependenciesAreNotDuplicated() {
        val payload = udp(sipMessage())
        val packets = listOf(
            ipv4(payload.copyOfRange(0, 80), 17, 10, 0x2000),
            ipv4(udp("unrelated".toByteArray()), 17, 11),
            ipv4(payload.copyOfRange(80, payload.size), 17, 10, 10)
        )
        checkExport(packets, listOf(0, 2), "sip || frame.number == 1", 2)
    }

    @Test
    fun unfilteredExportPreservesEveryRecord() {
        val payload = udp(sipMessage())
        val packets = listOf(
            ipv4(payload.copyOfRange(0, 80), 17, 10, 0x2000),
            ipv4(udp("unrelated".toByteArray()), 17, 11),
            ipv4(payload.copyOfRange(80, payload.size), 17, 10, 10)
        )
        checkExport(packets, listOf(0, 1, 2), "", 3)
    }

    @Test
    fun sipExportIncludesSctpDataFragments() {
        val message = sipMessage(transport = "SCTP")
        val packets = listOf(
            ipv4(sctp(sctpData(message.copyOfRange(0, 64), 100, 2)), 132, 1),
            ipv4(udp("unrelated".toByteArray()), 17, 2),
            ipv4(sctp(sctpData(message.copyOfRange(64, 128), 101, 0)), 132, 3),
            ipv4(sctp(sctpData(message.copyOfRange(128, message.size), 102, 1)), 132, 4)
        )
        checkExport(packets, listOf(0, 2, 3), "sip", 1)
    }

    @Test
    fun sipExportIncludesOutOfOrderUnorderedSctpDataFragments() {
        val message = sipMessage(transport = "SCTP")
        // U=1 denotes unordered delivery. The middle TSN arrives after the end.
        val packets = listOf(
            ipv4(sctp(sctpData(message.copyOfRange(0, 64), 100, 6)), 132, 1),
            ipv4(sctp(sctpData(message.copyOfRange(128, message.size), 102, 5)), 132, 2),
            ipv4(udp("unrelated".toByteArray()), 17, 3),
            ipv4(sctp(sctpData(message.copyOfRange(64, 128), 101, 4)), 132, 4)
        )
        checkExport(packets, listOf(0, 1, 3), "sip", 1)
    }

    @Test
    fun sipExportIncludesOnlySelectedInterleavedSctpIDataMessage() {
        val message = sipMessage(transport = "SCTP")
        val other = sipMessage("unrelated", transport = "SCTP")
        // The same stream carries interleaved messages, identified by MID/FSN.
        val packets = listOf(
            ipv4(sctp(sctpIData(message.copyOfRange(0, 64), 100, 2, 10, 0)), 132, 1),
            ipv4(sctp(sctpIData(other.copyOfRange(0, 64), 101, 2, 11, 0)), 132, 2),
            ipv4(sctp(sctpIData(message.copyOfRange(64, 128), 102, 0, 10, 1)), 132, 3),
            ipv4(sctp(sctpIData(other.copyOfRange(64, other.size), 103, 1, 11, 1)), 132, 4),
            ipv4(sctp(sctpIData(message.copyOfRange(128, message.size), 104, 1, 10, 2)), 132, 5)
        )
        checkExport(packets, listOf(0, 2, 4), "sip.Call-ID == \"export-fragments\"", 1)
    }

    @Test
    fun bundledSctpDataChunksArePreservedAsOnePacket() {
        val message = sipMessage(transport = "SCTP")
        // Non-aligned payload sizes also exercise the padding between chunks.
        val packets = listOf(
            ipv4(sctp(
                sctpData(message.copyOfRange(0, 61), 100, 2),
                sctpData(message.copyOfRange(61, 124), 101, 0),
                sctpData(message.copyOfRange(124, message.size), 102, 1)
            ), 132, 1),
            ipv4(udp("unrelated".toByteArray()), 17, 2)
        )
        checkExport(packets, listOf(0), "sip", 1)
    }

    @Test
    fun sipExportIncludesTransitiveIpAndSctpDependencies() {
        val message = sipMessage(transport = "SCTP")
        val firstChunkPacket = sctp(sctpData(message.copyOfRange(0, 128), 100, 2))
        val packets = listOf(
            ipv4(firstChunkPacket.copyOfRange(0, 80), 132, 10, 0x2000),
            ipv4(firstChunkPacket.copyOfRange(80, firstChunkPacket.size), 132, 10, 10),
            ipv4(udp("unrelated".toByteArray()), 17, 11),
            ipv4(sctp(sctpData(message.copyOfRange(128, message.size), 101, 1)), 132, 12)
        )
        checkExport(packets, listOf(0, 1, 3), "sip", 1)
    }

    private fun checkExport(
        packets: List<ByteArray>, expectedIndices: List<Int>, filter: String,
        visibleCount: Int, subsequentFrame: Int? = null
    ) {
        val source = File(context.cacheDir, "fragment-export-source.pcap")
        val output = File(context.cacheDir, "fragment-export-result.pcap")
        val records = packets.mapIndexed { index, packet ->
            ByteBuffer.allocate(16 + packet.size).order(ByteOrder.LITTLE_ENDIAN)
                .putInt(1_700_000_000 + index).putInt(index * 1000)
                .putInt(packet.size).putInt(packet.size).put(packet).array()
        }
        val header = ByteBuffer.allocate(24).order(ByteOrder.LITTLE_ENDIAN)
            .putInt(0xa1b2c3d4.toInt()).putShort(2).putShort(4)
            .putInt(0).putInt(0).putInt(65535).putInt(1).array()
        source.outputStream().use { stream ->
            stream.write(header)
            records.forEach(stream::write)
        }
        var session = 0L
        try {
            session = NativeEngine.openFile(source.absolutePath, null)
            assertNotEquals(NativeEngine.getLastError(), 0L, session)
            val applied = JSONObject(NativeEngine.applyDisplayFilter(session, filter))
            assertTrue(applied.toString(), applied.getBoolean("success"))
            assertEquals("Unexpected visible fixture count", visibleCount, applied.getInt("count"))
            repeat(2) {
                val exported = JSONObject(NativeEngine.exportVisibleCapture(session, output.absolutePath))
                assertTrue(exported.toString(), exported.getBoolean("success"))
                assertEquals("Export must include all reassembly dependencies", expectedIndices.size, exported.getInt("count"))
                assertArrayEquals(
                    "Preserve raw bytes, timestamps, order and uniqueness",
                    header + expectedIndices.fold(byteArrayOf()) { bytes, index -> bytes + records[index] },
                    output.readBytes()
                )
                assertEquals("Export must not expand the UI filter", visibleCount, NativeEngine.getFilteredFrameCount(session))
            }
            if (subsequentFrame != null) {
                NativeEngine.applyDisplayFilter(session, "frame.number == $subsequentFrame")
                val exported = JSONObject(NativeEngine.exportVisibleCapture(session, output.absolutePath))
                assertTrue(exported.toString(), exported.getBoolean("success"))
                assertEquals(1, exported.getInt("count"))
                assertArrayEquals(header + records[subsequentFrame - 1], output.readBytes())
            } else {
                NativeEngine.closeFile(session)
                session = 0L
                session = NativeEngine.openFile(output.absolutePath, null)
                assertNotEquals(NativeEngine.getLastError(), 0L, session)
                val reopened = JSONObject(NativeEngine.applyDisplayFilter(session, filter))
                assertTrue(reopened.toString(), reopened.getBoolean("success"))
                assertEquals("SIP must still reassemble after reopening the export", visibleCount, reopened.getInt("count"))
            }
        } finally {
            if (session != 0L) NativeEngine.closeFile(session)
            source.delete()
            output.delete()
        }
    }

    private fun sipMessage(callId: String = "export-fragments", transport: String = "TCP") = (
        "OPTIONS sip:bob@example.invalid SIP/2.0\r\n" +
            "Via: SIP/2.0/$transport 192.0.2.1:5060;branch=z9cH-export\r\n" +
            "From: <sip:alice@example.invalid>;tag=1\r\n" +
            "To: <sip:bob@example.invalid>\r\n" +
            "Call-ID: $callId\r\nCSeq: 1 OPTIONS\r\nContent-Length: 0\r\n\r\n"
        ).toByteArray()

    private fun tcpHandshake() = listOf(
        ipv4(tcp(byteArrayOf(), 100, flags = 2), 6, 1),
        ipv4(tcp(byteArrayOf(), 200, flags = 18, reverse = true), 6, 2, reverse = true),
        ipv4(tcp(byteArrayOf(), 101, flags = 16), 6, 3)
    )

    private fun tcp(data: ByteArray, sequence: Int, flags: Int = 24, reverse: Boolean = false): ByteArray =
        ByteBuffer.allocate(20 + data.size).apply {
            putShort(5060).putShort(5060).putInt(sequence).putInt(if (reverse) 101 else 201)
            put(0x50).put(flags.toByte()).putShort(65535.toShort()).putShort(0).putShort(0).put(data)
        }.array()

    private fun udp(data: ByteArray): ByteArray = ByteBuffer.allocate(8 + data.size)
        .putShort(5060).putShort(5060).putShort((8 + data.size).toShort()).putShort(0).put(data).array()

    private fun sctpData(data: ByteArray, tsn: Int, flags: Int): ByteArray =
        ByteBuffer.allocate(16 + data.size)
            .put(0).put(flags.toByte()).putShort((16 + data.size).toShort())
            .putInt(tsn).putShort(0).putShort(0).putInt(0).put(data).array()

    private fun sctpIData(data: ByteArray, tsn: Int, flags: Int, mid: Int, fsn: Int): ByteArray =
        ByteBuffer.allocate(20 + data.size)
            .put(64).put(flags.toByte()).putShort((20 + data.size).toShort())
            .putInt(tsn).putShort(0).putShort(0).putInt(mid)
            .putInt(if (flags and 2 != 0) 0 else fsn).put(data).array()

    private fun sctp(vararg chunks: ByteArray): ByteArray {
        val packet = ByteBuffer.allocate(12 + chunks.sumOf { (it.size + 3) and -4 }).apply {
            putShort(5060).putShort(5060).putInt(0x12345678).putInt(0)
            chunks.forEach { chunk ->
                put(chunk)
                repeat((4 - chunk.size % 4) % 4) { put(0) }
            }
        }.array()
        // SCTP stores its reflected CRC32C in little-endian byte order.
        var crc = -1
        packet.forEach { byte ->
            crc = crc xor (byte.toInt() and 255)
            repeat(8) { crc = (crc ushr 1) xor (if (crc and 1 != 0) 0x82f63b78.toInt() else 0) }
        }
        ByteBuffer.wrap(packet).order(ByteOrder.LITTLE_ENDIAN).putInt(8, crc.inv())
        return packet
    }

    private fun ipv4(data: ByteArray, protocol: Int, id: Int, fragment: Int = 0, reverse: Boolean = false): ByteArray {
        val header = ByteBuffer.allocate(20).apply {
            put(0x45).put(0).putShort((20 + data.size).toShort()).putShort(id.toShort())
            putShort(fragment.toShort()).put(64).put(protocol.toByte()).putShort(0)
            putInt(if (reverse) 0xc0000202.toInt() else 0xc0000201.toInt())
            putInt(if (reverse) 0xc0000201.toInt() else 0xc0000202.toInt())
        }.array()
        var sum = 0
        for (i in header.indices step 2) sum += ((header[i].toInt() and 255) shl 8) or (header[i + 1].toInt() and 255)
        while (sum > 65535) sum = (sum and 65535) + (sum ushr 16)
        ByteBuffer.wrap(header).putShort(10, sum.inv().toShort())
        return ethernet(0x0800) + header + data
    }

    private fun ipv6Fragment(data: ByteArray, offsetAndMore: Int): ByteArray =
        ethernet(0x86dd) + ByteBuffer.allocate(48 + data.size).apply {
            putInt(0x60000000).putShort((8 + data.size).toShort()).put(44).put(64)
            putLong(0x20010db800000000L).putLong(1)
            putLong(0x20010db800000000L).putLong(2)
            put(17).put(0).putShort(offsetAndMore.toShort()).putInt(42).put(data)
        }.array()

    private fun ethernet(type: Int) = ByteBuffer.allocate(14)
        .put(byteArrayOf(2, 0, 0, 0, 0, 2, 2, 0, 0, 0, 0, 1)).putShort(type.toShort()).array()

    companion object {
        private lateinit var context: Context

        @JvmStatic
        @BeforeClass
        fun initialize() {
            context = ApplicationProvider.getApplicationContext()
            // The Application owns process-wide epan initialization/cleanup.
            // Initializing it again here registers every dissector twice.
            val application = context as LayerAnalyzerApplication
            val state = runBlocking {
                withTimeout(30_000) {
                    application.engineState.first {
                        it !is EngineState.Initializing && it !is EngineState.RestoringSession
                    }
                }
            }
            assertTrue(state.toString(), state is EngineState.Ready || state is EngineState.AwaitingSessionRestore)
            application.repository.closeFile()
        }
    }
}
