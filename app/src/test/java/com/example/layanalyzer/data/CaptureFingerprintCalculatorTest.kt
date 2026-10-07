package com.example.layanalyzer.data

import org.junit.Assert.assertEquals
import org.junit.Test
import java.io.File

class CaptureFingerprintCalculatorTest {
    @Test
    fun calculatesStandardSha256() {
        val file = File.createTempFile("layer-analyzer-fingerprint", ".pcap")
        try {
            file.writeText("abc")
            assertEquals(
                "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad",
                CaptureFingerprintCalculator().calculate(file)
            )
        } finally {
            file.delete()
        }
    }
}
