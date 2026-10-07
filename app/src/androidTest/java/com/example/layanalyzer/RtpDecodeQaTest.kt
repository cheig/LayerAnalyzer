package com.example.layanalyzer

import android.content.Context
import android.os.ParcelFileDescriptor
import android.os.SystemClock
import android.util.Log
import androidx.test.core.app.ApplicationProvider
import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.platform.app.InstrumentationRegistry
import kotlinx.coroutines.flow.first
import kotlinx.coroutines.runBlocking
import kotlinx.coroutines.withTimeout
import org.json.JSONObject
import org.junit.After
import org.junit.AfterClass
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotEquals
import org.junit.Assert.assertTrue
import org.junit.Assume.assumeTrue
import org.junit.BeforeClass
import org.junit.Test
import org.junit.runner.RunWith
import java.io.File

/**
 * RTP2-QA-02: long-stream performance and decode failure cleanup.
 *
 * The long performance case is opt-in through the instrumentation argument
 * `rtpLongPcap`; it is skipped when no generated capture is supplied.
 */
@RunWith(AndroidJUnit4::class)
class RtpDecodeQaTest {

    @Test(timeout = 300_000)
    fun longG711DecodeMeetsPerformanceAndMemoryTargets() {
        val capturePath = InstrumentationRegistry.getArguments()
            .getString(ARG_LONG_PCAP)
        assumeTrue(
            "Pass -Pandroid.testInstrumentationRunnerArguments." +
                "$ARG_LONG_PCAP=<device path> to run this case.",
            !capturePath.isNullOrBlank()
        )
        val capture = File(requireNotNull(capturePath))
        assertTrue(
            "Long RTP pcap does not exist or is unreadable: $capture",
            capture.isFile && capture.canRead()
        )

        val previousHeuristic = NativeEngine.isRtpHeuristicEnabled()
        try {
            val heuristicResult =
                JSONObject(NativeEngine.setRtpHeuristicEnabled(true))
            assertEquals("", heuristicResult.optString("error"))
            val session = openCapture(capture)
            try {
                val scanStartMs = SystemClock.elapsedRealtime()
                val scan = scan(session)
                val scanMs = SystemClock.elapsedRealtime() - scanStartMs
                val stream = firstDecodableG711A(scan)
                val streamId = stream.getString("id")
                assertEquals(EXPECTED_PACKETS, stream.getLong("packets"))

                val outDir = File(appContext.cacheDir, "rtp-qa-long")
                outDir.deleteRecursively()

                // Stabilize the Java heap before taking the baseline dumpsys.
                System.gc()
                Thread.sleep(1_000)
                val beforeMemory = readProcessMemory("before")

                val decodeStartNanos = SystemClock.elapsedRealtimeNanos()
                val result = decode(
                    session = session,
                    scan = scan,
                    streamId = streamId,
                    mode = "jitter",
                    outDir = outDir,
                    progress = null
                )
                val decodeMs =
                    (SystemClock.elapsedRealtimeNanos() - decodeStartNanos) /
                        1_000_000L
                val afterMemory = readProcessMemory("after")

                val pssDeltaKiB = afterMemory.pssKiB - beforeMemory.pssKiB
                val rssDeltaKiB = afterMemory.rssKiB - beforeMemory.rssKiB
                Log.i(
                    TAG,
                    "long_decode scan_ms=$scanMs decode_ms=$decodeMs " +
                        "before_pss_kib=${beforeMemory.pssKiB} " +
                        "after_pss_kib=${afterMemory.pssKiB} " +
                        "pss_delta_kib=$pssDeltaKiB " +
                        "before_rss_kib=${beforeMemory.rssKiB} " +
                        "after_rss_kib=${afterMemory.rssKiB} " +
                        "rss_delta_kib=$rssDeltaKiB"
                )

                assertEquals("", result.optString("error"))
                assertFalse(result.optBoolean("cancelled", true))
                assertEquals(
                    0,
                    result.optJSONArray("unsupported")?.length() ?: 0
                )
                val item = requireNotNull(
                    result.optJSONArray("items")?.optJSONObject(0)
                ) {
                    "decodeRtpAudio returned no item: $result"
                }
                assertEquals(streamId, item.getString("streamId"))
                assertEquals(EXPECTED_DURATION_MS, item.getLong("durationMs"))
                val stats = item.getJSONObject("stats")
                assertEquals(EXPECTED_PACKETS, stats.getLong("decodedPackets"))
                assertEquals(0L, stats.getLong("droppedLate"))
                assertEquals(0L, stats.getLong("lost"))
                assertEquals(
                    EXPECTED_WAV_BYTES,
                    File(item.getString("wavPath")).length()
                )

                val targetFailures = buildList {
                    if (decodeMs >= MAX_DECODE_MS) {
                        add("decode ${decodeMs} ms >= ${MAX_DECODE_MS} ms")
                    }
                    if (pssDeltaKiB >= MAX_MEMORY_DELTA_KIB) {
                        add(
                            "PSS delta ${pssDeltaKiB} KiB >= " +
                                "${MAX_MEMORY_DELTA_KIB} KiB"
                        )
                    }
                }
                assertTrue(
                    "30-minute G.711 targets failed: " +
                        targetFailures.joinToString("; ") +
                        " (RSS delta ${rssDeltaKiB} KiB)",
                    targetFailures.isEmpty()
                )
            } finally {
                NativeEngine.closeFile(session)
            }
        } finally {
            NativeEngine.setRtpHeuristicEnabled(previousHeuristic)
        }
    }

    @Test(timeout = 60_000)
    fun unwritableOutputDirectoryFailsWithoutResidue() {
        val session = openCapture(fixtureCapture)
        try {
            val scan = scan(session)
            val streamId = firstDecodableG711A(scan).getString("id")
            val outDir = File("/proc/x")
            assertFalse(
                "Test precondition failed: /proc/x already exists",
                outDir.exists()
            )

            val result = decode(
                session,
                scan,
                streamId,
                "jitter",
                outDir,
                null
            )
            assertTrue(
                "decodeRtpAudio unexpectedly accepted /proc/x: $result",
                result.optString("error").isNotEmpty()
            )
            assertFalse(result.optBoolean("cancelled", true))
            assertEquals(0, result.optJSONArray("items")?.length() ?: 0)
            assertFalse(
                "Unwritable output directory left residue: $outDir",
                outDir.exists()
            )
        } finally {
            NativeEngine.closeFile(session)
        }
    }

    @Test(timeout = 60_000)
    fun cancellationAfterPartialPayloadWriteCleansOutputDirectory() {
        val session = openCapture(fixtureCapture)
        try {
            val scan = scan(session)
            val streamId = firstDecodableG711A(scan).getString("id")
            val outDir = File(appContext.cacheDir, "rtp-qa-cancel")
            outDir.deleteRecursively()

            var sawPartialOutput = false
            val result = decode(
                session,
                scan,
                streamId,
                "jitter",
                outDir
            ) { _, _ ->
                val partial = outDir.listFiles().orEmpty().any { file ->
                    file.isFile && file.length() > 0L
                }
                if (partial) {
                    sawPartialOutput = true
                }
                !partial
            }

            assertTrue(
                "Cancellation was not triggered after a partial output file " +
                    "became visible; result=$result",
                sawPartialOutput
            )
            assertTrue(
                "Cancelled decode must report cancelled=true: $result",
                result.optBoolean("cancelled", false)
            )
            assertEquals("", result.optString("error"))
            assertEquals(0, result.optJSONArray("items")?.length() ?: 0)
            assertTrue(
                "Cancelled decode left output files: " +
                    outDir.listFiles().orEmpty().joinToString(),
                !outDir.exists() || outDir.listFiles().orEmpty().isEmpty()
            )
        } finally {
            NativeEngine.closeFile(session)
        }
    }

    private fun openCapture(capture: File): Long {
        val session = NativeEngine.openFile(capture.absolutePath, null)
        assertNotEquals(
            "openFile failed: ${NativeEngine.getLastError()}",
            0L,
            session
        )
        return session
    }

    private fun scan(session: Long): JSONObject {
        val result = JSONObject(
            NativeEngine.scanRtpStreams(
                session,
                "{\"limitToDisplayFilter\":false}",
                null
            )
        )
        assertEquals(
            "scanRtpStreams reported an error: ${result.optString("error")}",
            "",
            result.optString("error")
        )
        assertFalse(result.optBoolean("cancelled", true))
        return result
    }

    private fun firstDecodableG711A(scan: JSONObject): JSONObject {
        val streams = requireNotNull(scan.optJSONArray("streams"))
        for (index in 0 until streams.length()) {
            val stream = streams.getJSONObject(index)
            if (stream.optString("codec") == "g711A" &&
                stream.optString("decodable") == "yes"
            ) {
                return stream
            }
        }
        throw AssertionError("No decodable G.711A stream was found: $scan")
    }

    private fun decode(
        session: Long,
        scan: JSONObject,
        streamId: String,
        mode: String,
        outDir: File,
        progress: NativeEngine.RtpProgressCallback?
    ): JSONObject {
        val request = JSONObject()
            .put("scanGeneration", scan.getLong("scanGeneration"))
            .put("streams", org.json.JSONArray().put(streamId))
            .put("timing", mode)
            .put("jitterMs", 50)
        return JSONObject(
            NativeEngine.decodeRtpAudio(
                session,
                request.toString(),
                outDir.absolutePath,
                progress
            )
        )
    }

    private fun readProcessMemory(label: String): ProcessMemory {
        val automation = InstrumentationRegistry.getInstrumentation().uiAutomation
        val descriptor = automation.executeShellCommand(
            "dumpsys meminfo $APP_ID"
        )
        val output = ParcelFileDescriptor.AutoCloseInputStream(descriptor)
            .use { input ->
                input.bufferedReader(Charsets.UTF_8).readText()
            }
        val pss = TOTAL_PSS.find(output)?.groupValues?.get(1)?.toLongOrNull()
        val rss = TOTAL_RSS.find(output)?.groupValues?.get(1)?.toLongOrNull()
        requireNotNull(pss) {
            "Unable to parse TOTAL PSS from dumpsys meminfo ($label)"
        }
        requireNotNull(rss) {
            "Unable to parse TOTAL RSS from dumpsys meminfo ($label)"
        }
        val totals = output.lineSequence()
            .filter { it.contains("TOTAL PSS") || it.contains("TOTAL RSS") }
            .joinToString(" | ")
        Log.i(
            TAG,
            "dumpsys_$label pss_kib=$pss rss_kib=$rss raw=\"$totals\""
        )
        return ProcessMemory(pss, rss)
    }

    @After
    fun cleanOutputs() {
        appContext.cacheDir.listFiles()
            .orEmpty()
            .filter { it.name == "rtp-qa-long" || it.name == "rtp-qa-cancel" }
            .forEach(File::deleteRecursively)
    }

    private data class ProcessMemory(
        val pssKiB: Long,
        val rssKiB: Long
    )

    companion object {
        @JvmStatic
        @AfterClass
        fun cleanupFixture() {
            if (::fixtureCapture.isInitialized) {
                fixtureCapture.delete()
            }
        }

        private const val TAG = "RTP2-QA-02"
        private const val APP_ID = "com.layeranalyzer.android"
        private const val ARG_LONG_PCAP = "rtpLongPcap"
        private const val EXPECTED_PACKETS = 90_000L
        private const val EXPECTED_DURATION_MS = 1_800_000L
        private const val EXPECTED_WAV_BYTES =
            44L + EXPECTED_PACKETS * 160L * 2L
        private const val MAX_DECODE_MS = 3_000L
        private const val MAX_MEMORY_DELTA_KIB = 30L * 1024L
        private val TOTAL_PSS = Regex("""TOTAL PSS:\s*(\d+)""")
        private val TOTAL_RSS = Regex("""TOTAL RSS:\s*(\d+)""")

        private lateinit var appContext: Context
        private lateinit var testContext: Context
        private lateinit var fixtureCapture: File

        @JvmStatic
        @BeforeClass
        fun initializeEngine() {
            appContext = ApplicationProvider.getApplicationContext()
            testContext = InstrumentationRegistry.getInstrumentation().context
            val application = appContext as LayerAnalyzerApplication

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
                        application.engineState.first {
                            it is EngineState.Ready || it is EngineState.Failed
                        }
                    }
                }
            }
            assertTrue(
                (engineState as? EngineState.Failed)?.message
                    ?: "Native engine did not initialize.",
                engineState is EngineState.Ready
            )
            copyAssetFolder(
                appContext,
                "wireshark-data",
                File(appContext.filesDir, "wireshark-data")
            )
            fixtureCapture = copyAssetFile(
                testContext,
                "rtp/sip_g711a_bidirectional.pcap",
                File(appContext.cacheDir, "rtp-qa-fixture.pcap")
            )
        }

        private fun copyAssetFolder(
            context: Context,
            assetPath: String,
            targetDir: File
        ) {
            targetDir.mkdirs()
            val children = context.assets.list(assetPath).orEmpty()
            if (children.isEmpty()) {
                copyAssetFile(context, assetPath, targetDir)
                return
            }
            for (child in children) {
                val childAssetPath = "$assetPath/$child"
                val grandChildren = context.assets.list(childAssetPath).orEmpty()
                if (grandChildren.isEmpty()) {
                    copyAssetFile(
                        context,
                        childAssetPath,
                        File(targetDir, child)
                    )
                } else {
                    copyAssetFolder(
                        context,
                        childAssetPath,
                        File(targetDir, child)
                    )
                }
            }
        }

        private fun copyAssetFile(
            context: Context,
            assetPath: String,
            targetFile: File
        ): File {
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
