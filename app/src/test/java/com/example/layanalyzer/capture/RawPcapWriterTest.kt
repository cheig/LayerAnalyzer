package com.example.layanalyzer.capture

import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Test
import java.io.ByteArrayOutputStream
import java.nio.ByteBuffer
import java.nio.ByteOrder

class RawPcapWriterTest {
    @Test
    fun writesLittleEndianHeaderAndPacketRecord() {
        val output = ByteArrayOutputStream()
        RawPcapWriter(output).use { writer ->
            writer.writeHeader()
            writer.writePacket(1_234L, byteArrayOf(0x45, 0x00, 0x01, 0x02), 3)
        }

        val bytes = output.toByteArray()
        val buffer = ByteBuffer.wrap(bytes).order(ByteOrder.LITTLE_ENDIAN)
        assertEquals(0xa1b2c3d4.toInt(), buffer.int)
        assertEquals(2, buffer.short.toInt())
        assertEquals(4, buffer.short.toInt())
        assertEquals(0, buffer.int)
        assertEquals(0, buffer.int)
        assertEquals(65_535, buffer.int)
        assertEquals(101, buffer.int)
        assertEquals(1, buffer.int)
        assertEquals(234_000, buffer.int)
        assertEquals(3, buffer.int)
        assertEquals(3, buffer.int)
        assertArrayEquals(byteArrayOf(0x45, 0x00, 0x01), bytes.copyOfRange(40, 43))
    }
}
