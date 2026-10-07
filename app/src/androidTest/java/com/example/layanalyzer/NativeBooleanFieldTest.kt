// Copyright (c) 2026 cheig
// LayerAnalyzer - https://github.com/cheig/LayerAnalyzer
// Licensed under GNU GPL version 3; see LICENSE.

package com.example.layanalyzer

import androidx.test.core.app.ApplicationProvider
import androidx.test.ext.junit.runners.AndroidJUnit4
import kotlinx.coroutines.flow.first
import kotlinx.coroutines.runBlocking
import kotlinx.coroutines.withTimeout
import org.json.JSONObject
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotEquals
import org.junit.Assert.assertTrue
import org.junit.Test
import org.junit.runner.RunWith
import java.io.BufferedOutputStream
import java.io.File
import java.io.OutputStream

@RunWith(AndroidJUnit4::class)
class NativeBooleanFieldTest {
    @Test
    fun tcpBooleanFieldsCanBeReadWhileBuildingStatistics() {
        val application = ApplicationProvider.getApplicationContext<LayerAnalyzerApplication>()
        var engineState = runBlocking {
            withTimeout(30_000) {
                application.engineState.first {
                    it is EngineState.Ready ||
                        it is EngineState.Failed ||
                        it is EngineState.AwaitingSessionRestore
                }
            }
        }
        if (engineState is EngineState.AwaitingSessionRestore) {
            application.declineSessionRestore()
            engineState = runBlocking {
                withTimeout(30_000) {
                    application.engineState.first { it is EngineState.Ready || it is EngineState.Failed }
                }
            }
        }
        assertTrue(
            (engineState as? EngineState.Failed)?.message ?: "Native engine did not initialize.",
            engineState is EngineState.Ready
        )

        val tcpCapture = File(application.cacheDir, "native-tcp-syn.pcap")
        writeSyntheticTcpSynCapture(tcpCapture)
        val session = NativeEngine.openFile(tcpCapture.absolutePath, null)
        assertNotEquals("openFile failed: ${NativeEngine.getLastError()}", 0L, session)
        try {
            val statistics = JSONObject(NativeEngine.buildStatistics(session, 1.0))
            assertEquals(1, statistics.getInt("packetCount"))
            assertEquals(1, statistics.getInt("tcpSyn"))
            assertEquals(0, statistics.getInt("tcpSynAck"))
        } finally {
            NativeEngine.closeFile(session)
            tcpCapture.delete()
        }
    }

    private fun writeSyntheticTcpSynCapture(file: File) {
        val packet = byteArrayOf(
            0x00, 0x11, 0x22, 0x33, 0x44, 0x55,
            0x66, 0x77, 0x00, 0x11, 0x22, 0x33,
            0x08, 0x00,
            0x45, 0x00, 0x00, 0x28, 0x00, 0x00, 0x00, 0x00,
            0x40, 0x06, 0x00, 0x00,
            0xc0.toByte(), 0x00, 0x02, 0x01,
            0xc6.toByte(), 0x33, 0x64, 0x02,
            0x30, 0x39, 0x00, 0x50,
            0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00,
            0x50, 0x02, 0x20, 0x00,
            0x00, 0x00, 0x00, 0x00
        )
        BufferedOutputStream(file.outputStream()).use { output ->
            writeLeInt(output, 0xa1b2c3d4.toInt())
            writeLeShort(output, 2)
            writeLeShort(output, 4)
            writeLeInt(output, 0)
            writeLeInt(output, 0)
            writeLeInt(output, 65_535)
            writeLeInt(output, 1)
            writeLeInt(output, 0)
            writeLeInt(output, 0)
            writeLeInt(output, packet.size)
            writeLeInt(output, packet.size)
            output.write(packet)
        }
    }

    private fun writeLeShort(output: OutputStream, value: Int) {
        output.write(value and 0xff)
        output.write(value ushr 8 and 0xff)
    }

    private fun writeLeInt(output: OutputStream, value: Int) {
        output.write(value and 0xff)
        output.write(value ushr 8 and 0xff)
        output.write(value ushr 16 and 0xff)
        output.write(value ushr 24 and 0xff)
    }
}
