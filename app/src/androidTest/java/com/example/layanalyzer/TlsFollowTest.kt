// Copyright (c) 2026 cheig; GPL-3.0.
package com.example.layanalyzer

import android.util.Base64
import org.json.JSONObject
import androidx.test.ext.junit.runners.AndroidJUnit4
import org.junit.Assert.*
import org.junit.Before
import org.junit.Test
import org.junit.runner.RunWith
import java.io.ByteArrayOutputStream
import java.io.File
import java.nio.ByteBuffer
import java.nio.ByteOrder
import java.util.concurrent.Executors
import java.util.concurrent.TimeUnit

/** Production follower only, probe OFF; no skipped or simulated decryption. */
@RunWith(AndroidJUnit4::class)
class TlsFollowTest {
    @Before fun engineReady() { NativeTestSupport.awaitApplicationEngine() }

    @Test fun tls12BidirectionalBytesAndResponseOnlyFilter() = roundTrip("tls12-h1")
    @Test fun tls13BidirectionalBytesAndResponseOnlyFilter() = roundTrip("tls13-h1")
    @Test fun tls13Http2ApplicationBytes() = roundTrip("tls13-h2")

    private fun roundTrip(id: String) = TlsPassiveFixture(id).use { fixture ->
        val handle = fixture.open()
        try {
            val generation = configure(handle, fixture.file("keylog").path, 1)
            // Select the last response/teardown frame before any detail read.
            // Follow must prime from the beginning, not parse the selection first.
            val result = follow(handle, NativeEngine.getFrameCount(handle) - 1, generation)
            assertTrue(result.getBoolean("directionKnown"))
            assertFalse(result.getBoolean("truncated"))
            assertFalse(result.getBoolean("incomplete"))
            assertKnownBytes(fixture, result)
            val records = result.getJSONArray("records")
            val serverFrame = (0 until records.length()).map { records.getJSONObject(it) }
                .first { it.getString("direction") == "server" }.getInt("frameNumber")
            val filtered = JSONObject(NativeEngine.applyDisplayFilter(handle, "tcp.srcport == ${fixture.port}"))
            assertTrue(filtered.optString("error").isEmpty())
            assertTrue(NativeEngine.getFilteredFrameCount(handle) < NativeEngine.getFrameCount(handle))
            val responseSelection = follow(handle, serverFrame - 1, generation)
            assertEquals(result.getJSONArray("records").toString(), responseSelection.getJSONArray("records").toString())
            assertEquals(generation, responseSelection.getLong("dissectionGeneration"))
            // Old TCP follower remains explicitly scoped to the filtered set.
            val tcp = JSONObject(NativeEngine.followStream(handle, serverFrame - 1, "tcp"))
            assertEquals("tcp", tcp.getString("protocol"))
            assertEquals("current filtered packet set", tcp.getString("scope"))
        } finally { fixture.closeCapture(handle) }
    }

    @Test fun absentWrongClearedAndMissingHandshakeHaveNoSuccessEmptyStream() =
        TlsPassiveFixture("tls13-h1").use { fixture ->
            var handle = fixture.open()
            try {
                var generation = configure(handle, null, 1)
                unavailable(handle, generation, "SECRETS_NOT_CONFIGURED")
                generation = configure(handle, fixture.file("wrong-keylog").path, 2)
                unavailable(handle, generation, "NO_DECRYPTED_APPLICATION_DATA")
                generation = configure(handle, fixture.file("keylog").path, 3)
                val valid = follow(handle, 0, generation)
                val firstData = valid.getJSONArray("records").getJSONObject(0).getInt("frameNumber")
                generation = configure(handle, null, 4)
                unavailable(handle, generation, "SECRETS_NOT_CONFIGURED")
                fixture.closeCapture(handle)
                handle = 0
                val missing = File(fixture.directory, "follow-derived-missing-handshake.pcap")
                try {
                    rewrite(fixture.file("pcap"), missing) { index, packet ->
                        if (index + 1 >= firstData) listOf(packet) else emptyList()
                    }
                    handle = openDerived(fixture, missing)
                    generation = configure(handle, fixture.file("keylog").path, 1)
                    unavailable(handle, generation, "HANDSHAKE_INCOMPLETE")
                } finally {
                    if (handle != 0L) { fixture.closeCapture(handle); handle = 0 }
                    assertTrue(missing.delete())
                }
            } finally { if (handle != 0L) fixture.closeCapture(handle) }
        }

    @Test fun budgetsGenerationAndHandleErrorsAreStructured() {
        TlsPassiveFixture("tls12-h1").use { fixture ->
        val handle = fixture.open()
        var generation = 0L
        try {
            generation = configure(handle, fixture.file("keylog").path, 1)
            val complete = follow(handle, 0, generation)
            for (budget in listOf(1, 7, complete.getInt("byteLength") - 1)) {
                val limited = follow(handle, 0, generation, budget)
                assertTrue(limited.getBoolean("truncated"))
                assertTrue(limited.getBoolean("incomplete"))
                assertEquals(budget, limited.getInt("byteLength"))
                assertArrayEquals(bytes(complete).copyOf(budget), bytes(limited))
            }
            val exact = follow(handle, 0, generation, complete.getInt("byteLength"))
            assertFalse(exact.getBoolean("truncated"))
            assertArrayEquals(bytes(complete), bytes(exact))
            for (budget in listOf(-1, 0, 1024 * 1024 + 1, Int.MAX_VALUE)) {
                error("INVALID_ARGUMENT", NativeEngine.followTlsStream(handle, 0, generation, budget))
            }
            error("INVALID_ARGUMENT", NativeEngine.followTlsStream(handle, -1, generation, 100))
            error("INVALID_ARGUMENT", NativeEngine.followTlsStream(handle, Int.MAX_VALUE, generation, 100))
            error("STALE_GENERATION", NativeEngine.followTlsStream(handle, 0, generation + 1, 100))
            configure(handle, null, 2)
            error("STALE_GENERATION", NativeEngine.followTlsStream(handle, 0, generation, 100))
        } finally { fixture.closeCapture(handle) }
        error("NOT_READY", NativeEngine.followTlsStream(handle, 0, generation, 100))
        }
    }

    @Test fun splitTcpSegmentsAndRetransmissionsPreserveApplicationBytes() =
        TlsPassiveFixture("tls13-h1").use { fixture ->
            var handle = fixture.open()
            val expected: JSONObject
            try { expected = follow(handle, 0, configure(handle, fixture.file("keylog").path, 1)) }
            finally { fixture.closeCapture(handle) }
            val transformed = File(fixture.directory, "split-retransmit.pcap")
            var splitCount = 0
            try {
                rewrite(fixture.file("pcap"), transformed) { _, packet ->
                    // Canonical DLT_NULL / IPv4 / TCP. Split every payload > 8 B
                    // inside its TLS record, then duplicate both TCP segments.
                    val ip = 4
                    val tcp = ip + (packet[ip].toInt() and 15) * 4
                    val headerEnd = tcp + ((packet[tcp + 12].toInt() ushr 4) and 15) * 4
                    val payloadSize = packet.size - headerEnd
                    if (payloadSize <= 8) listOf(packet) else {
                        ++splitCount
                        val cut = payloadSize / 2
                        val first = packet.copyOf(headerEnd + cut)
                        val second = packet.copyOf(headerEnd) + packet.copyOfRange(headerEnd + cut, packet.size)
                        val seq = ByteBuffer.wrap(packet, tcp + 4, 4).int
                        ByteBuffer.wrap(second, tcp + 4, 4).putInt(seq + cut)
                        first[tcp + 13] = (first[tcp + 13].toInt() and 0xf6).toByte() // FIN/PSH only on last segment
                        listOf(first, second).forEach { fixChecksums(it, ip, tcp) }
                        listOf(first, first, second, second)
                    }
                }
                assertTrue(splitCount > 0)
                handle = openDerived(fixture, transformed)
                try {
                    val actual = follow(handle, 0, configure(handle, fixture.file("keylog").path, 1))
                    assertKnownBytes(fixture, actual)
                    for (direction in listOf("client", "server"))
                        assertArrayEquals(bytes(expected, direction), bytes(actual, direction))
                    assertFalse(actual.getBoolean("truncated"))
                } finally { fixture.closeCapture(handle) }
            } finally { assertTrue(transformed.delete()) }
        }

    @Test fun cancelledScanDoesNotPublishPartialRecordsAndNextFollowWorks() = TlsPassiveFixture("tls12-h1").use { fixture ->
        val large = File(fixture.directory, "cancel-follow.pcap")
        try {
            rewrite(fixture.file("pcap"), large) { index, packet ->
                if (index == 0) List(20_000) { packet } else listOf(packet)
            }
            val handle = openDerived(fixture, large)
            val executor = Executors.newSingleThreadExecutor()
            try {
                val generation = configure(handle, fixture.file("keylog").path, 1)
                val pending = executor.submit<String> { NativeEngine.followTlsStream(handle, 0, generation, MAX_BYTES) }
                val deadline = System.nanoTime() + TimeUnit.SECONDS.toNanos(30)
                while (!pending.isDone && System.nanoTime() < deadline) {
                    NativeEngine.cancelLongRunningOperations()
                    Thread.sleep(2)
                }
                error("CANCELLED", pending.get(5, TimeUnit.SECONDS))
                assertKnownBytes(fixture, follow(handle, 0, generation))
            } finally {
                executor.shutdownNow()
                assertTrue(executor.awaitTermination(5, TimeUnit.SECONDS))
                fixture.closeCapture(handle)
            }
        } finally { assertTrue(large.delete()) }
    }

    private fun assertKnownBytes(fixture: TlsPassiveFixture, result: JSONObject) =
        fixture.assertApplicationBytes(bytes(result, "client"), bytes(result, "server"))

    private fun bytes(result: JSONObject, direction: String? = null): ByteArray = ByteArrayOutputStream().also { out ->
        val records = result.getJSONArray("records")
        var previousFrame = 0
        for (index in 0 until records.length()) {
            val record = records.getJSONObject(index)
            assertTrue(record.getInt("frameNumber") >= previousFrame)
            previousFrame = record.getInt("frameNumber")
            val bytes = Base64.decode(record.getString("bytesBase64"), Base64.NO_WRAP)
            assertEquals(record.getInt("byteLength"), bytes.size)
            assertEquals(record.getString("direction") == "server", record.getBoolean("fromServer"))
            if (direction == null || direction == record.getString("direction")) out.write(bytes)
        }
    }.toByteArray()

    private fun follow(handle: Long, index: Int, generation: Long, budget: Int = MAX_BYTES): JSONObject =
        success(NativeEngine.followTlsStream(handle, index, generation, budget)).also {
            assertEquals("tls", it.getString("protocol"))
            assertEquals("complete_connection", it.getString("scope"))
            assertEquals(generation, it.getLong("dissectionGeneration"))
            assertEquals(it.getInt("byteLength"), bytes(it).size)
        }

    private fun unavailable(handle: Long, generation: Long, reason: String) {
        val result = error("NOT_READY", NativeEngine.followTlsStream(handle, 0, generation, MAX_BYTES))
        assertTrue(result.getBoolean("incomplete"))
        assertEquals(reason, result.getString("unavailableReason"))
    }

    private fun configure(handle: Long, path: String?, revision: Long) =
        success(NativeEngine.configureTlsSecrets(handle, path, revision)).getLong("dissectionGeneration")

    private fun success(raw: String) = JSONObject(raw).also {
        assertEquals(1, it.getInt("schemaVersion"))
        assertTrue("Production JNI must succeed: ${it.optString("errorCode")}", it.getBoolean("success"))
        assertTrue(it.isNull("errorCode") && it.isNull("error"))
    }

    private fun error(code: String, raw: String) = JSONObject(raw).also {
        assertEquals(1, it.getInt("schemaVersion"))
        assertFalse(it.getBoolean("success"))
        assertEquals(code, it.getString("errorCode"))
        assertEquals(0, it.getJSONArray("records").length())
    }

    private fun openDerived(fixture: TlsPassiveFixture, file: File): Long = NativeEngine.openFile(file.path, null).also {
        assertTrue(it != 0L)
        // applyDecodeAs predates the common envelope and answers with success/error only.
        assertTrue(JSONObject(NativeEngine.applyDecodeAs(it, "tcp.port", fixture.port, "tls")).getBoolean("success"))
    }

    /** Derive only from manifest-verified public synthetic captures, in noBackupFilesDir. */
    private fun rewrite(input: File, output: File, transform: (Int, ByteArray) -> List<ByteArray>) {
        val source = input.readBytes()
        val buffer = ByteBuffer.wrap(source).order(ByteOrder.LITTLE_ENDIAN)
        assertEquals(0xa1b2c3d4.toInt(), buffer.int)
        assertEquals(0, buffer.getInt(20)) // Canonical host-loopback DLT_NULL.
        output.outputStream().buffered().use { out ->
            out.write(source, 0, 24)
            var offset = 24
            var index = 0
            while (offset < source.size) {
                val size = buffer.getInt(offset + 8)
                val header = source.copyOfRange(offset, offset + 16)
                val packet = source.copyOfRange(offset + 16, offset + 16 + size)
                for (changed in transform(index++, packet)) {
                    ByteBuffer.wrap(header).order(ByteOrder.LITTLE_ENDIAN).apply {
                        putInt(8, changed.size); putInt(12, changed.size)
                    }
                    out.write(header); out.write(changed)
                }
                offset += 16 + size
            }
        }
    }

    private fun fixChecksums(packet: ByteArray, ip: Int, tcp: Int) {
        fun checksum(bytes: ByteArray): Int {
            var sum = 0L
            for (offset in bytes.indices step 2)
                sum += ((bytes[offset].toInt() and 255) shl 8) +
                    if (offset + 1 < bytes.size) bytes[offset + 1].toInt() and 255 else 0
            while (sum ushr 16 != 0L) sum = (sum and 65535) + (sum ushr 16)
            return sum.toInt().inv() and 65535
        }
        val buffer = ByteBuffer.wrap(packet)
        buffer.putShort(ip + 2, (packet.size - ip).toShort())
        buffer.putShort(ip + 10, 0)
        buffer.putShort(tcp + 16, 0)
        buffer.putShort(ip + 10, checksum(packet.copyOfRange(ip, tcp)).toShort())
        val pseudo = packet.copyOfRange(ip + 12, ip + 20) + byteArrayOf(0, 6) +
            ByteBuffer.allocate(2).putShort((packet.size - tcp).toShort()).array()
        buffer.putShort(tcp + 16, checksum(pseudo + packet.copyOfRange(tcp, packet.size)).toShort())
    }

    private companion object { const val MAX_BYTES = 1024 * 1024 }
}
