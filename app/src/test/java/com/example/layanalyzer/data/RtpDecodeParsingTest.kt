package com.example.layanalyzer.data

import com.example.layanalyzer.model.RtpRawOrder
import com.example.layanalyzer.model.RtpTimingMode
import org.json.JSONObject
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertThrows
import org.junit.Assert.assertTrue
import org.junit.Rule
import org.junit.Test
import org.junit.rules.TemporaryFolder
import java.nio.ByteBuffer
import java.nio.ByteOrder

class RtpDecodeParsingTest {
    @get:Rule
    val temporaryFolder = TemporaryFolder()

    private val repository = RtpRepository(PacketRepository())

    @Test
    fun `peaks reader parses little endian header and samples`() {
        val bytes = ByteBuffer.allocate(24)
            .order(ByteOrder.LITTLE_ENDIAN)
            .put("PKS1".toByteArray(Charsets.US_ASCII))
            .putInt(8_000)
            .putInt(80)
            .putInt(2)
            .putShort((-32_768).toShort())
            .putShort(32_767.toShort())
            .putShort((-1).toShort())
            .putShort(1)
            .array()
        val file = temporaryFolder.newFile("s0.peaks").apply {
            writeBytes(bytes)
        }

        val (header, peaks) = PeaksFile.read(file)

        assertEquals(8_000, header.sampleRate)
        assertEquals(80, header.samplesPerBucket)
        assertEquals(2, header.count)
        assertArrayEquals(
            shortArrayOf(-32_768, 32_767, -1, 1),
            peaks
        )
    }

    @Test
    fun `frame map reader parses entries and frameAt handles boundaries`() {
        val bytes = ByteBuffer.allocate(24)
            .order(ByteOrder.LITTLE_ENDIAN)
            .put("MAP1".toByteArray(Charsets.US_ASCII))
            .putInt(2)
            .putInt(10)
            .putInt(100)
            .putInt(20)
            .putInt(0xffffffff.toInt())
            .array()
        val file = temporaryFolder.newFile("s0.map").apply {
            writeBytes(bytes)
        }

        val entries = FrameMapFile.read(file)

        assertEquals(
            listOf(
                FrameMapFile.Entry(atMs = 10L, frame = 100L),
                FrameMapFile.Entry(atMs = 20L, frame = 0xffffffffL)
            ),
            entries
        )
        assertNull(FrameMapFile.frameAt(ms = 0L, entries = emptyList()))
        assertEquals(100L, FrameMapFile.frameAt(ms = 0L, entries))
        assertEquals(100L, FrameMapFile.frameAt(ms = 10L, entries))
        assertEquals(100L, FrameMapFile.frameAt(ms = 15L, entries))
        assertEquals(0xffffffffL, FrameMapFile.frameAt(ms = 20L, entries))
        assertEquals(0xffffffffL, FrameMapFile.frameAt(ms = 99L, entries))
    }

    @Test
    fun `wav reader parses pcm header and data length`() {
        val bytes = ByteBuffer.allocate(48)
            .order(ByteOrder.LITTLE_ENDIAN)
            .put("RIFF".toByteArray(Charsets.US_ASCII))
            .putInt(40)
            .put("WAVE".toByteArray(Charsets.US_ASCII))
            .put("fmt ".toByteArray(Charsets.US_ASCII))
            .putInt(16)
            .putShort(1)
            .putShort(1)
            .putInt(8_000)
            .putInt(16_000)
            .putShort(2)
            .putShort(16)
            .put("data".toByteArray(Charsets.US_ASCII))
            .putInt(4)
            .putShort(1)
            .putShort(2)
            .array()
        val file = temporaryFolder.newFile("s0.wav").apply {
            writeBytes(bytes)
        }

        val info = WavHeader.parse(file)

        assertEquals(8_000, info?.sampleRate)
        assertEquals(1, info?.channels)
        assertEquals(16, info?.bitsPerSample)
        assertEquals(4L, info?.dataBytes)
        assertEquals(2L, info?.frameCount)
    }

    @Test
    fun `binary readers reject invalid magic`() {
        val peaks = temporaryFolder.newFile("bad.peaks").apply {
            writeBytes("NOPE".toByteArray(Charsets.US_ASCII))
        }
        val map = temporaryFolder.newFile("bad.map").apply {
            writeBytes("NOPE".toByteArray(Charsets.US_ASCII))
        }
        val wav = temporaryFolder.newFile("bad.wav").apply {
            writeBytes("NOPE".toByteArray(Charsets.US_ASCII))
        }

        assertThrows(IllegalArgumentException::class.java) {
            PeaksFile.read(peaks)
        }
        assertThrows(IllegalArgumentException::class.java) {
            FrameMapFile.read(map)
        }
        assertNull(WavHeader.parse(wav))
    }

    @Test
    fun `decode response parses every field`() {
        val result = repository.parseDecodeResult(
            """
            {
              "schemaVersion": 1,
              "error": "",
              "cancelled": false,
              "items": [{
                "streamId": "s0",
                "codec": "g711A",
                "sampleRate": 8000,
                "channels": 1,
                "wavPath": "/cache/s0.wav",
                "peaksPath": "/cache/s0.peaks",
                "mapPath": "/cache/s0.map",
                "durationMs": 30400,
                "startRel": 1.02,
                "startAbsEpochMs": 1726000000000,
                "gaps": [{
                  "atMs": 1200,
                  "durMs": 40,
                  "reason": "lost",
                  "clipped": true,
                  "frame": 99
                }],
                "events": [{
                  "atMs": 5000,
                  "type": "ptChange",
                  "value": "101",
                  "frame": 123
                }],
                "stats": {
                  "decodedPackets": 1497,
                  "droppedLate": 2,
                  "lost": 3,
                  "truncatedPackets": 4,
                  "zeroPayloadPackets": 5
                }
              }],
              "unsupported": [{
                "streamId": "s2",
                "reason": "srtp"
              }]
            }
            """.trimIndent()
        )

        assertTrue(result.isSuccess)
        assertEquals("", result.error)
        assertFalse(result.cancelled)
        val item = result.items.single()
        assertEquals("s0", item.streamId)
        assertEquals("g711A", item.codec)
        assertEquals(8_000, item.sampleRate)
        assertEquals(1, item.channels)
        assertEquals("/cache/s0.wav", item.wavPath)
        assertEquals("/cache/s0.peaks", item.peaksPath)
        assertEquals("/cache/s0.map", item.mapPath)
        assertEquals(30_400L, item.durationMs)
        assertEquals(1.02, item.startRel, 0.0)
        assertEquals(1_726_000_000_000L, item.startAbsEpochMs)
        assertEquals(
            com.example.layanalyzer.model.RtpGap(
                atMs = 1_200L,
                durMs = 40L,
                reason = "lost",
                clipped = true,
                frame = 99L
            ),
            item.gaps.single()
        )
        assertEquals(
            com.example.layanalyzer.model.RtpEvent(
                atMs = 5_000L,
                type = "ptChange",
                value = "101",
                frame = 123L
            ),
            item.events.single()
        )
        assertEquals(1_497L, item.stats.decodedPackets)
        assertEquals(2L, item.stats.droppedLate)
        assertEquals(3L, item.stats.lost)
        assertEquals(4L, item.stats.truncatedPackets)
        assertEquals(5L, item.stats.zeroPayloadPackets)
        assertEquals("s2", result.unsupported.single().streamId)
        assertEquals("srtp", result.unsupported.single().reason)
    }

    @Test
    fun `decode response uses defaults for missing fields`() {
        val result = repository.parseDecodeResult(
            """{"items":[{}],"unsupported":[{}]}"""
        )

        val item = result.items.single()
        assertEquals("", item.streamId)
        assertEquals("", item.codec)
        assertEquals(0, item.sampleRate)
        assertEquals(0, item.channels)
        assertEquals("", item.wavPath)
        assertEquals("", item.peaksPath)
        assertEquals("", item.mapPath)
        assertEquals(0L, item.durationMs)
        assertEquals(0.0, item.startRel, 0.0)
        assertEquals(0L, item.startAbsEpochMs)
        assertTrue(item.gaps.isEmpty())
        assertTrue(item.events.isEmpty())
        assertEquals(0L, item.stats.decodedPackets)
        assertEquals(0L, item.stats.droppedLate)
        assertEquals(0L, item.stats.lost)
        assertEquals(0L, item.stats.truncatedPackets)
        assertEquals(0L, item.stats.zeroPayloadPackets)
        assertEquals("", result.unsupported.single().streamId)
        assertEquals("", result.unsupported.single().reason)
        assertTrue(result.isSuccess)
    }

    @Test
    fun `decode response tolerates unknown fields`() {
        val result = repository.parseDecodeResult(
            """
            {
              "futureTopLevel": {"x": 1},
              "items": [{
                "streamId": "s0",
                "futureItem": true,
                "stats": {"decodedPackets": 7, "futureStat": 9}
              }],
              "unsupported": []
            }
            """.trimIndent()
        )

        assertEquals("s0", result.items.single().streamId)
        assertEquals(7L, result.items.single().stats.decodedPackets)
        assertTrue(result.isSuccess)
    }

    @Test
    fun `decode response with error is not successful`() {
        val result = repository.parseDecodeResult(
            """{"error":"Unable to create RTP output directory.","cancelled":false}"""
        )

        assertFalse(result.isSuccess)
        assertEquals(
            "Unable to create RTP output directory.",
            result.error
        )
        assertTrue(result.items.isEmpty())
    }

    @Test
    fun `cancelled decode response is not successful`() {
        val result = repository.parseDecodeResult(
            """{"error":"","cancelled":true}"""
        )

        assertFalse(result.isSuccess)
        assertTrue(result.cancelled)
    }

    @Test
    fun `malformed decode response is rejected`() {
        val result = repository.parseDecodeResult("not json")

        assertFalse(result.isSuccess)
        assertEquals("Malformed RTP decode response.", result.error)
        assertTrue(result.items.isEmpty())
        assertTrue(result.unsupported.isEmpty())
    }

    @Test
    fun `request builders use the native wire contract`() {
        val decode = JSONObject(
            repository.buildDecodeRequest(
                com.example.layanalyzer.model.RtpDecodeRequest(
                    scanGeneration = 7L,
                    streamIds = listOf("s0", "s1"),
                    timing = RtpTimingMode.RTP_TIMESTAMP,
                    jitterMs = 75
                )
            )
        )
        assertEquals(7L, decode.getLong("scanGeneration"))
        assertEquals(
            listOf("s0", "s1"),
            List(decode.getJSONArray("streams").length()) {
                decode.getJSONArray("streams").getString(it)
            }
        )
        assertEquals("rtp", decode.getString("timing"))
        assertEquals(75, decode.getInt("jitterMs"))

        val raw = JSONObject(
            repository.buildRawExportRequest(
                scanGeneration = 8L,
                streamId = "s2",
                order = RtpRawOrder.ARRIVAL
            )
        )
        assertEquals(8L, raw.getLong("scanGeneration"))
        assertEquals("s2", raw.getString("streamId"))
        assertEquals("arrival", raw.getString("order"))
    }

    @Test
    fun `raw export response parses bytes packets and error`() {
        val success = repository.parseRawExportResult(
            """{"schemaVersion":1,"bytes":123456,"packets":1497,"error":""}"""
        )
        val failure = repository.parseRawExportResult(
            """{"schemaVersion":1,"bytes":0,"packets":0,"error":"staleScan"}"""
        )

        assertTrue(success.isSuccess)
        assertEquals(123_456L, success.bytes)
        assertEquals(1_497L, success.packets)
        assertFalse(failure.isSuccess)
        assertEquals("staleScan", failure.error)
    }
}
