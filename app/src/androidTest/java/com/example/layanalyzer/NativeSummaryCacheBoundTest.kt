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
class NativeSummaryCacheBoundTest {
    @Test
    fun cacheRemainsBoundedAndFilterChangesInvalidateSummaries() {
        val application = ApplicationProvider.getApplicationContext<LayerAnalyzerApplication>()
        awaitEngineReady(application)

        val frameCount = MAX_CACHE_ENTRIES + 2
        val capture = File(application.cacheDir, "native-summary-bound.pcap")
        writeSyntheticUdpCapture(capture, frames = frameCount)
        val session = NativeEngine.openFile(capture.absolutePath, null)
        assertNotEquals("openFile failed: ${NativeEngine.getLastError()}", 0L, session)
        try {
            var stats = JSONObject(NativeEngine.getSummaryCacheStats(session))
            assertEquals(0, stats.getInt("valid"))
            assertEquals(0L, stats.getLong("bytes"))

            // Traverse more frames than the entry limit; opening the capture
            // and paging it must never allocate a summary for every frame.
            for (start in 0 until frameCount step 128) {
                NativeEngine.getPacketSummaries(session, start, minOf(128, frameCount - start))
                stats = JSONObject(NativeEngine.getSummaryCacheStats(session))
                assertTrue(stats.getInt("entries") <= MAX_CACHE_ENTRIES)
                assertTrue(stats.getLong("bytes") <= MAX_CACHE_BYTES)
            }
            assertTrue(stats.getLong("evictions") > 0)
            assertEquals(frameCount.toLong(), stats.getLong("misses"))

            val misses = stats.getLong("misses")
            NativeEngine.getPacketSummaries(session, 0, 2)
            stats = JSONObject(NativeEngine.getSummaryCacheStats(session))
            assertEquals(misses + 2, stats.getLong("misses"))
            val hits = stats.getLong("hits")
            NativeEngine.getPacketSummaries(session, 0, 2)
            stats = JSONObject(NativeEngine.getSummaryCacheStats(session))
            assertEquals(hits + 2, stats.getLong("hits"))

            val filter = JSONObject(
                NativeEngine.applyDisplayFilter(session, "frame.number >= 1")
            )
            assertTrue(filter.optString("error"), filter.getBoolean("success"))
            stats = JSONObject(NativeEngine.getSummaryCacheStats(session))
            assertEquals(0, stats.getInt("valid"))
            assertEquals(0L, stats.getLong("bytes"))
            assertEquals(0L, stats.getLong("hits"))
            assertEquals(0L, stats.getLong("misses"))

            NativeEngine.getPacketSummaries(session, 0, 2)
            val cleared = JSONObject(NativeEngine.applyDisplayFilter(session, ""))
            assertTrue(cleared.optString("error"), cleared.getBoolean("success"))
            stats = JSONObject(NativeEngine.getSummaryCacheStats(session))
            assertEquals(0, stats.getInt("valid"))
            assertEquals(0L, stats.getLong("bytes"))
        } finally {
            NativeEngine.closeFile(session)
            capture.delete()
        }
    }

    private fun awaitEngineReady(application: LayerAnalyzerApplication) {
        var state = runBlocking {
            withTimeout(30_000) {
                application.engineState.first {
                    it is EngineState.Ready ||
                        it is EngineState.Failed ||
                        it is EngineState.AwaitingSessionRestore
                }
            }
        }
        if (state is EngineState.AwaitingSessionRestore) {
            application.declineSessionRestore()
            state = runBlocking {
                withTimeout(30_000) {
                    application.engineState.first {
                        it is EngineState.Ready || it is EngineState.Failed
                    }
                }
            }
        }
        assertTrue(
            (state as? EngineState.Failed)?.message ?: "Native engine did not initialize.",
            state is EngineState.Ready
        )
    }

    private fun writeSyntheticUdpCapture(file: File, frames: Int) {
        val packet = byteArrayOf(
            0x00, 0x11, 0x22, 0x33, 0x44, 0x55,
            0x66, 0x77, 0x00, 0x11, 0x22, 0x33,
            0x08, 0x00,
            0x45, 0x00, 0x00, 0x1c, 0x00, 0x00, 0x00, 0x00,
            0x40, 0x11, 0x00, 0x00,
            0xc0.toByte(), 0x00, 0x02, 0x01,
            0xc6.toByte(), 0x33, 0x64, 0x02,
            0x30, 0x39, 0x00, 0x35, 0x00, 0x08, 0x00, 0x00
        )
        BufferedOutputStream(file.outputStream(), 64 * 1024).use { output ->
            writeLeInt(output, 0xa1b2c3d4.toInt())
            writeLeShort(output, 2)
            writeLeShort(output, 4)
            writeLeInt(output, 0)
            writeLeInt(output, 0)
            writeLeInt(output, 65_535)
            writeLeInt(output, 1)
            repeat(frames) { frame ->
                writeLeInt(output, frame / 1_000)
                writeLeInt(output, frame % 1_000 * 1_000)
                writeLeInt(output, packet.size)
                writeLeInt(output, packet.size)
                output.write(packet)
            }
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

    private companion object {
        const val MAX_CACHE_ENTRIES = 8192
        const val MAX_CACHE_BYTES = 16L * 1024 * 1024
    }
}
