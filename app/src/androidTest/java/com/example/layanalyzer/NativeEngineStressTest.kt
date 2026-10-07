// Copyright (c) 2026 cheig
// LayerAnalyzer - https://github.com/cheig/LayerAnalyzer
// Licensed under GNU GPL version 3; see LICENSE.

package com.example.layanalyzer

import android.content.Context
import android.os.SystemClock
import androidx.test.ext.junit.runners.AndroidJUnit4
import com.example.layanalyzer.data.AgentAnalysisRepository
import com.example.layanalyzer.data.CaptureSessionCoordinator
import com.example.layanalyzer.data.PacketRepository
import com.example.layanalyzer.model.AnalysisScope
import kotlinx.coroutines.runBlocking
import org.junit.AfterClass
import org.junit.Assert.assertFalse
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotEquals
import org.junit.Assert.assertTrue
import org.junit.BeforeClass
import org.junit.Test
import org.junit.runner.RunWith
import java.io.File
import java.io.BufferedOutputStream
import java.io.OutputStream
import java.util.concurrent.CountDownLatch
import java.util.concurrent.Executors
import java.util.concurrent.TimeUnit
import org.json.JSONObject

@RunWith(AndroidJUnit4::class)
class NativeEngineStressTest {
    @Test
    fun repeatedOpenCloseKeepsSessionLifecycleStable() {
        var previousHandle = 0L
        repeat(OPEN_CLOSE_ITERATIONS) {
            val session = NativeEngine.openFile(captureFile.absolutePath, null)
            assertNotEquals("openFile failed on iteration $it: ${NativeEngine.getLastError()}", 0L, session)
            if (previousHandle != 0L) {
                assertNotEquals("Session handles must not be immediately reused", previousHandle, session)
            }
            assertTrue("Expected at least one frame on iteration $it", NativeEngine.getFrameCount(session) > 0)
            NativeEngine.closeFile(session)
            assertEquals("Closed session handle remained valid", 0, NativeEngine.getFrameCount(session))
            NativeEngine.closeFile(session)
            previousHandle = session
        }
    }

    @Test
    fun repeatedDetailLoadingKeepsDissectionStable() {
        val session = NativeEngine.openFile(captureFile.absolutePath, null)
        assertNotEquals("openFile failed: ${NativeEngine.getLastError()}", 0L, session)
        try {
            val frameCount = NativeEngine.getFrameCount(session)
            assertTrue("Expected test capture to contain frames", frameCount > 0)

            repeat(DETAIL_LOAD_ITERATIONS) { iteration ->
                val packetIndex = iteration % frameCount
                val details = NativeEngine.getPacketDetails(session, packetIndex)
                assertFalse("Details were empty on iteration $iteration", details.isBlank())
                assertTrue("Details did not contain the packet root on iteration $iteration", details.contains("Packet ${packetIndex + 1}"))

                val bytes = NativeEngine.getPacketBytes(session, packetIndex)
                assertTrue("Packet bytes were empty on iteration $iteration", bytes.isNotEmpty())
            }
        } finally {
            NativeEngine.closeFile(session)
        }
    }

    @Test
    fun packetSummariesExposeWiresharkInfoColumn() {
        val infoCapture = File(appContext.cacheDir, "native-info-column.pcap")
        writeSyntheticUdpCapture(infoCapture, frames = 1)
        val session = NativeEngine.openFile(infoCapture.absolutePath, null)
        assertNotEquals("openFile failed: ${NativeEngine.getLastError()}", 0L, session)
        try {
            val summary = NativeEngine.getPacketSummaries(session, 0, 1).single()
            assertTrue(
                "Wireshark Info column was empty for a valid UDP packet",
                summary.info.isNotBlank()
            )
        } finally {
            NativeEngine.closeFile(session)
            infoCapture.delete()
        }
    }

    @Test
    fun nativeStatisticsAndExportMatchVisibleFrames() {
        val session = NativeEngine.openFile(captureFile.absolutePath, null)
        assertNotEquals("openFile failed: ${NativeEngine.getLastError()}", 0L, session)
        try {
            val frameCount = NativeEngine.getFrameCount(session)
            val summaries = NativeEngine.getPacketSummaries(session, 0, frameCount)
            val statistics = JSONObject(NativeEngine.buildStatistics(session, 1.0))
            assertEquals(frameCount, statistics.getInt("packetCount"))
            assertEquals(summaries.sumOf { it.length.toLong() }, statistics.getLong("byteCount"))

            val output = File(appContext.cacheDir, "native-visible-export.pcap")
            val export = JSONObject(NativeEngine.exportVisibleCapture(session, output.absolutePath))
            assertTrue(export.optString("error"), export.getBoolean("success"))
            assertEquals(frameCount, export.getInt("count"))
            assertEquals(frameCount, countClassicPcapRecords(output.readBytes()))

            val filtered = JSONObject(NativeEngine.applyDisplayFilter(session, "frame.number == 1"))
            assertTrue(filtered.optString("error"), filtered.getBoolean("success"))
            assertEquals(1, filtered.getInt("count"))
            assertEquals(1, JSONObject(NativeEngine.buildStatistics(session, 1.0)).getInt("packetCount"))
        } finally {
            NativeEngine.applyDisplayFilter(session, "")
            NativeEngine.closeFile(session)
        }
    }

    @Test
    fun agentFilterLeaseRestoresRealNativeSession() = runBlocking {
        val repository = PacketRepository()
        val coordinator = CaptureSessionCoordinator(repository)
        val info = repository.openFile(captureFile.absolutePath).getOrThrow()
        val token = coordinator.onSessionOpened(info)
        try {
            assertTrue(coordinator.prepareFingerprint(token, captureFile).isSuccess)
            val original = coordinator.applyUserFilter("frame.number >= 1", token)
            assertTrue(original.success)
            val originalCount = repository.getVisibleFrameCount()
            val agentRepository = AgentAnalysisRepository(repository, coordinator)
            val snapshot = checkNotNull(
                agentRepository.createSnapshot(AnalysisScope.CompleteFile).getOrNull()
            )

            val result = agentRepository.queryWithTemporaryFilter(
                snapshot,
                "frame.number == 1"
            ) { reader ->
                reader.getVisibleFrameCount()
            }

            assertTrue(result.success)
            assertEquals(1, result.getOrNull())
            assertEquals("frame.number >= 1", repository.getAppliedDisplayFilter())
            assertEquals(originalCount, repository.getVisibleFrameCount())
        } finally {
            coordinator.invalidateSession()
            repository.closeFile()
        }
    }

    @Test
    fun nativeExportPreservesRecordLengthsAndRejectsUnsupportedEncapsulation() {
        val truncatedCapture = File(appContext.cacheDir, "native-truncated-source.pcap")
        val truncatedExport = File(appContext.cacheDir, "native-truncated-export.pcap")
        writeSyntheticUdpCapture(
            truncatedCapture,
            frames = 1,
            originalLength = 64
        )
        val truncatedSession = NativeEngine.openFile(truncatedCapture.absolutePath, null)
        assertNotEquals("Unable to open truncated capture", 0L, truncatedSession)
        try {
            val export = JSONObject(
                NativeEngine.exportVisibleCapture(truncatedSession, truncatedExport.absolutePath)
            )
            assertTrue(export.optString("error"), export.getBoolean("success"))
            val bytes = truncatedExport.readBytes()
            assertEquals(SYNTHETIC_FRAME_SIZE, readLittleEndianInt(bytes, 24 + 8))
            assertEquals(64, readLittleEndianInt(bytes, 24 + 12))
        } finally {
            NativeEngine.closeFile(truncatedSession)
            truncatedCapture.delete()
            truncatedExport.delete()
        }

        val unsupportedCapture = File(appContext.cacheDir, "native-unsupported-source.pcap")
        val unsupportedExport = File(appContext.cacheDir, "native-unsupported-export.pcap")
        unsupportedExport.delete()
        writeSyntheticUdpCapture(
            unsupportedCapture,
            frames = 1,
            linkType = 147
        )
        val unsupportedSession = NativeEngine.openFile(unsupportedCapture.absolutePath, null)
        assertNotEquals("Unable to open unsupported capture", 0L, unsupportedSession)
        try {
            val export = JSONObject(
                NativeEngine.exportVisibleCapture(unsupportedSession, unsupportedExport.absolutePath)
            )
            assertFalse(export.toString(), export.getBoolean("success"))
            assertTrue(export.getString("error").contains("encapsulation", ignoreCase = true))
            assertFalse(unsupportedExport.exists())
        } finally {
            NativeEngine.closeFile(unsupportedSession)
            unsupportedCapture.delete()
            unsupportedExport.delete()
        }
    }

    @Test
    fun concurrentPagingAndLongScansStayStable() {
        val session = NativeEngine.openFile(captureFile.absolutePath, null)
        assertNotEquals("openFile failed: ${NativeEngine.getLastError()}", 0L, session)
        val executor = Executors.newFixedThreadPool(3)
        try {
            val frameCount = NativeEngine.getFrameCount(session)
            val work = listOf(
                executor.submit {
                    repeat(20) {
                        assertEquals(frameCount, JSONObject(NativeEngine.buildStatistics(session, 0.1)).getInt("packetCount"))
                    }
                },
                executor.submit {
                    repeat(100) {
                        assertEquals(frameCount, NativeEngine.getPacketSummaries(session, 0, frameCount).size)
                    }
                },
                executor.submit {
                    repeat(20) {
                        NativeEngine.searchPackets(session, "text", "TCP")
                        assertTrue(JSONObject(NativeEngine.applyDisplayFilter(session, "")).getBoolean("success"))
                    }
                }
            )
            work.forEach { it.get(60, TimeUnit.SECONDS) }
        } finally {
            executor.shutdownNow()
            executor.awaitTermination(5, TimeUnit.SECONDS)
            NativeEngine.closeFile(session)
        }
    }

    @Test
    fun largeStatisticsYieldToPagingAndCancelPromptly() {
        val largeCapture = File(appContext.cacheDir, "native-statistics-100k.pcap")
        writeSyntheticUdpCapture(largeCapture, LARGE_CAPTURE_FRAMES)
        val session = NativeEngine.openFile(largeCapture.absolutePath, null)
        assertNotEquals("openFile failed: ${NativeEngine.getLastError()}", 0L, session)
        val executor = Executors.newSingleThreadExecutor()
        try {
            val scanStarted = CountDownLatch(1)
            val startedAt = SystemClock.elapsedRealtime()
            val statisticsFuture = executor.submit<String> {
                scanStarted.countDown()
                NativeEngine.buildStatistics(session, 1.0)
            }
            assertTrue(scanStarted.await(5, TimeUnit.SECONDS))
            SystemClock.sleep(100)

            val pageStartedAt = SystemClock.elapsedRealtime()
            val page = NativeEngine.getPacketSummaries(session, 0, 50)
            val pageMillis = SystemClock.elapsedRealtime() - pageStartedAt
            assertEquals(50, page.size)
            assertTrue("Paging was blocked for ${pageMillis}ms by statistics", pageMillis < 5_000)

            val statistics = JSONObject(statisticsFuture.get(90, TimeUnit.SECONDS))
            val statisticsMillis = SystemClock.elapsedRealtime() - startedAt
            assertEquals(LARGE_CAPTURE_FRAMES, statistics.getInt("packetCount"))
            assertEquals(LARGE_CAPTURE_FRAMES * SYNTHETIC_FRAME_SIZE.toLong(), statistics.getLong("byteCount"))
            assertTrue("100k-frame statistics took ${statisticsMillis}ms", statisticsMillis < 90_000)
            val conversations = statistics.getJSONArray("conversations")
            val udpConversation = (0 until conversations.length())
                .map { conversations.getJSONObject(it) }
                .first { it.getString("type") == "UDP" }
            assertEquals(setOf(12_345, 53), setOf(udpConversation.getInt("portA"), udpConversation.getInt("portB")))

            val exportedCapture = File(appContext.cacheDir, "native-export-100k.pcap")
            val exportStartedAt = SystemClock.elapsedRealtime()
            val export = JSONObject(NativeEngine.exportVisibleCapture(session, exportedCapture.absolutePath))
            val exportMillis = SystemClock.elapsedRealtime() - exportStartedAt
            assertTrue(export.optString("error"), export.getBoolean("success"))
            assertEquals(LARGE_CAPTURE_FRAMES, export.getInt("count"))
            assertEquals(
                24L + LARGE_CAPTURE_FRAMES * (16L + SYNTHETIC_FRAME_SIZE),
                exportedCapture.length()
            )
            assertTrue("100k-frame export took ${exportMillis}ms", exportMillis < 30_000)
            exportedCapture.delete()

            val filterStarted = CountDownLatch(1)
            val supersededFilter = executor.submit<String> {
                filterStarted.countDown()
                NativeEngine.applyDisplayFilter(session, "udp")
            }
            assertTrue(filterStarted.await(5, TimeUnit.SECONDS))
            SystemClock.sleep(100)
            val clearFilter = JSONObject(NativeEngine.applyDisplayFilter(session, ""))
            assertTrue(clearFilter.optString("error"), clearFilter.getBoolean("success"))
            supersededFilter.get(10, TimeUnit.SECONDS)
            assertEquals(LARGE_CAPTURE_FRAMES, NativeEngine.getFilteredFrameCount(session))

            val searchStarted = CountDownLatch(1)
            val cancelledSearch = executor.submit<IntArray> {
                searchStarted.countDown()
                NativeEngine.searchPackets(session, "text", "UDP")
            }
            assertTrue(searchStarted.await(5, TimeUnit.SECONDS))
            SystemClock.sleep(100)
            NativeEngine.cancelSearch(session)
            assertTrue(
                "Cancelled search returned partial results",
                cancelledSearch.get(10, TimeUnit.SECONDS).isEmpty()
            )

            val cancelStarted = CountDownLatch(1)
            val cancelledFuture = executor.submit<String> {
                cancelStarted.countDown()
                NativeEngine.buildStatistics(session, 1.0)
            }
            assertTrue(cancelStarted.await(5, TimeUnit.SECONDS))
            SystemClock.sleep(100)
            val cancelAt = SystemClock.elapsedRealtime()
            NativeEngine.cancelLongRunningOperations()
            val cancelled = JSONObject(cancelledFuture.get(10, TimeUnit.SECONDS))
            assertTrue(cancelled.optBoolean("cancelled"))
            assertTrue("Cancellation took too long", SystemClock.elapsedRealtime() - cancelAt < 5_000)
        } finally {
            executor.shutdownNow()
            executor.awaitTermination(5, TimeUnit.SECONDS)
            NativeEngine.closeFile(session)
            largeCapture.delete()
        }
    }

    companion object {
        private const val OPEN_CLOSE_ITERATIONS = 25
        private const val DETAIL_LOAD_ITERATIONS = 100
        private const val LARGE_CAPTURE_FRAMES = 100_000
        private const val SYNTHETIC_FRAME_SIZE = 42
        private lateinit var appContext: Context
        private lateinit var captureFile: File

        private fun writeSyntheticUdpCapture(
            file: File,
            frames: Int,
            originalLength: Int = SYNTHETIC_FRAME_SIZE,
            linkType: Int = 1
        ) {
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
                writeLeInt(output, linkType)
                repeat(frames) { frame ->
                    writeLeInt(output, frame / 1_000)
                    writeLeInt(output, frame % 1_000 * 1_000)
                    writeLeInt(output, packet.size)
                    writeLeInt(output, originalLength)
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

        private fun countClassicPcapRecords(bytes: ByteArray): Int {
            require(bytes.size >= 24) { "Missing pcap header" }
            require(readLittleEndianInt(bytes, 0) == 0xa1b2c3d4.toInt()) { "Unexpected pcap magic" }
            var offset = 24
            var records = 0
            while (offset < bytes.size) {
                require(offset + 16 <= bytes.size) { "Truncated pcap record header" }
                val capturedLength = readLittleEndianInt(bytes, offset + 8)
                require(capturedLength >= 0 && offset + 16L + capturedLength <= bytes.size) {
                    "Invalid pcap record length"
                }
                offset += 16 + capturedLength
                records++
            }
            return records
        }

        private fun readLittleEndianInt(bytes: ByteArray, offset: Int): Int =
            (bytes[offset].toInt() and 0xff) or
                ((bytes[offset + 1].toInt() and 0xff) shl 8) or
                ((bytes[offset + 2].toInt() and 0xff) shl 16) or
                ((bytes[offset + 3].toInt() and 0xff) shl 24)

        @JvmStatic
        @BeforeClass
        fun initializeEngine() {
            appContext = NativeTestSupport.awaitApplicationEngine()
            captureFile = copyAssetFile(appContext, "test.pcap", File(appContext.cacheDir, "native-stress-test.pcap"))
        }

        @JvmStatic
        @AfterClass
        fun cleanupCapture() {
            // Keep the application-owned engine alive for subsequent test classes.
            captureFile.delete()
        }

        private fun copyAssetFile(context: Context, assetPath: String, targetFile: File): File {
            targetFile.parentFile?.mkdirs()
            context.assets.open(assetPath).use { input ->
                targetFile.outputStream().use { output ->
                    input.copyTo(output)
                }
            }
            return targetFile
        }
    }
}
