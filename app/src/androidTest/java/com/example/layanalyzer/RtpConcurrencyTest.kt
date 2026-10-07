package com.example.layanalyzer

import android.content.Context
import android.os.ParcelFileDescriptor
import androidx.test.core.app.ApplicationProvider
import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.platform.app.InstrumentationRegistry
import kotlinx.coroutines.flow.first
import kotlinx.coroutines.runBlocking
import kotlinx.coroutines.withTimeout
import org.json.JSONObject
import org.junit.AfterClass
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotEquals
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertTrue
import org.junit.BeforeClass
import org.junit.Test
import org.junit.runner.RunWith
import java.io.File
import java.util.Collections
import java.util.concurrent.CountDownLatch
import java.util.concurrent.ExecutorService
import java.util.concurrent.Executors
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicReference

/**
 * RTP1-QA-02: concurrency, cancellation and close-file safety for RTP scans.
 *
 * The progress callback is used as a deterministic overlap point.  The scan
 * thread is inside a real `scanRtpStreams` call when it signals the latch and
 * waits, while the test thread performs the competing operation.  No case
 * serializes the scan before claiming concurrency.
 */
@RunWith(AndroidJUnit4::class)
class RtpConcurrencyTest {

    @Test(timeout = 30_000)
    fun displayFilterChangeDuringScanIsSafe() {
        val session = openCapture()
        val baselineCrashLogs = nativeCrashLogLines()
        val scan = ConcurrentScan(session)
        try {
            scan.start()
            scan.awaitProgress("display-filter")

            val filterResult = JSONObject(NativeEngine.applyDisplayFilter(session, "rtp"))
            assertTrue(
                "applyDisplayFilter failed while scan was active: result=$filterResult " +
                    "lastError=${NativeEngine.getLastError()}",
                filterResult.optBoolean("success", false)
            )
            assertTrue(
                "applyDisplayFilter matched no RTP frames: result=$filterResult " +
                    "lastError=${NativeEngine.getLastError()}",
                filterResult.optInt("count", 0) > 0
            )

            val result = scan.releaseAndAwait("display-filter")
            assertCompleteOrCancelled(result, expectedStreamCount = 2, label = "display-filter")

            val newCrashLogs = nativeCrashLogLines() - baselineCrashLogs
            assertTrue(
                "Native crash logs appeared during display-filter concurrency: " +
                    "newLines=$newCrashLogs lastError=${NativeEngine.getLastError()}",
                newCrashLogs.isEmpty()
            )
        } finally {
            scan.shutdown()
            NativeEngine.closeFile(session)
        }
    }

    @Test(timeout = 30_000)
    fun pagingDuringScanReturnsRequestedPageSize() {
        val session = openCapture()
        val frameCount = NativeEngine.getFrameCount(session)
        assertTrue(
            "Capture has no frames: frameCount=$frameCount " +
                "lastError=${NativeEngine.getLastError()}",
            frameCount > 0
        )
        val expectedPageSize = minOf(PAGE_SIZE, frameCount)

        val scan = ConcurrentScan(session)
        val pagerDone = CountDownLatch(1)
        val pagerFailure = AtomicReference<Throwable?>()
        val observedSizes = Collections.synchronizedList(mutableListOf<Int>())
        val pager = newNamedExecutor("RTP-QA02-pager")
        try {
            scan.start()
            scan.awaitProgress("paging")

            pager.execute {
                try {
                    repeat(PAGING_ITERATIONS) {
                        val page = NativeEngine.getPacketSummaries(session, 0, PAGE_SIZE)
                        observedSizes.add(page.size)
                        if (page.size != expectedPageSize) {
                            throw AssertionError(
                                "getPacketSummaries returned wrong size during scan: " +
                                    "iteration=$it expected=$expectedPageSize actual=${page.size} " +
                                    "lastError=${NativeEngine.getLastError()}"
                            )
                        }
                    }
                } catch (failure: Throwable) {
                    pagerFailure.set(failure)
                } finally {
                    pagerDone.countDown()
                }
            }

            assertTrue(
                "Concurrent paging did not finish within 20s: " +
                    "lastError=${NativeEngine.getLastError()}",
                pagerDone.await(20, TimeUnit.SECONDS)
            )
            pagerFailure.get()?.let { failure ->
                throw AssertionError(
                    "Concurrent paging failed: lastError=${NativeEngine.getLastError()}",
                    failure
                )
            }
            assertEquals(
                "Concurrent paging returned inconsistent page sizes: " +
                    "observed=${observedSizes.toList()} lastError=${NativeEngine.getLastError()}",
                List(PAGING_ITERATIONS) { expectedPageSize },
                observedSizes.toList()
            )

            val result = scan.releaseAndAwait("paging")
            assertCompleteOrCancelled(result, expectedStreamCount = 2, label = "paging")
        } finally {
            scan.shutdown()
            pager.shutdownNow()
            pager.awaitTermination(5, TimeUnit.SECONDS)
            NativeEngine.closeFile(session)
        }
    }

    @Test(timeout = 30_000)
    fun cancellationDuringScanReturnsNoPartialStreams() {
        val session = openCapture()
        val scan = ConcurrentScan(session)
        try {
            scan.start()
            scan.awaitProgress("cancel")
            Thread.sleep(50)
            NativeEngine.cancelLongRunningOperations()

            val result = scan.releaseAndAwait("cancel")
            assertTrue(
                "Cancelled scan must report cancelled=true: result=$result " +
                    "lastError=${NativeEngine.getLastError()}",
                result.optBoolean("cancelled", false)
            )
            val streams = result.optJSONArray("streams")
            assertNotNull(
                "Cancelled scan omitted streams array: result=$result " +
                    "lastError=${NativeEngine.getLastError()}",
                streams
            )
            assertEquals(
                "Cancelled scan must not return partial streams: result=$result " +
                    "lastError=${NativeEngine.getLastError()}",
                0,
                streams!!.length()
            )
        } finally {
            scan.shutdown()
            NativeEngine.closeFile(session)
        }
    }

    @Test(timeout = 30_000)
    fun closeDuringScanInvalidatesSession() {
        val session = openCapture()
        val scan = ConcurrentScan(session)
        var sessionClosed = false
        try {
            scan.start()
            scan.awaitProgress("close")
            Thread.sleep(50)
            NativeEngine.closeFile(session)
            sessionClosed = true

            val result = scan.releaseAndAwait("close")
            val error = result.optString("error")
            val cancelled = result.optBoolean("cancelled", false)
            assertTrue(
                "Scan after concurrent close must return an error or cancelled=true: " +
                    "result=$result lastError=${NativeEngine.getLastError()}",
                error.isNotEmpty() || cancelled
            )
            val streams = result.optJSONArray("streams")
            assertNotNull(
                "Scan after concurrent close omitted streams array: result=$result " +
                    "lastError=${NativeEngine.getLastError()}",
                streams
            )
            assertEquals(
                "Scan after concurrent close must not return partial streams: result=$result " +
                    "lastError=${NativeEngine.getLastError()}",
                0,
                streams!!.length()
            )

            val oldHandleResult = JSONObject(
                NativeEngine.scanRtpStreams(session, SCAN_REQUEST, null)
            )
            assertFalse(
                "Old handle must be rejected after closeFile: result=$oldHandleResult " +
                    "lastError=${NativeEngine.getLastError()}",
                oldHandleResult.optString("error").isEmpty()
            )
        } finally {
            scan.shutdown()
            if (!sessionClosed) {
                NativeEngine.closeFile(session)
            }
        }
    }

    private fun openCapture(): Long {
        val session = NativeEngine.openFile(captureFile.absolutePath, null)
        assertNotEquals(
            "openFile failed: lastError=${NativeEngine.getLastError()}",
            0L,
            session
        )
        return session
    }

    private fun assertCompleteOrCancelled(
        result: JSONObject,
        expectedStreamCount: Int,
        label: String
    ) {
        val streams = result.optJSONArray("streams")
        assertNotNull(
            "$label scan omitted streams array: result=$result " +
                "lastError=${NativeEngine.getLastError()}",
            streams
        )
        if (result.optBoolean("cancelled", false)) {
            assertEquals(
                "$label scan was cancelled but returned partial streams: result=$result " +
                    "lastError=${NativeEngine.getLastError()}",
                0,
                streams!!.length()
            )
        } else {
            assertEquals(
                "$label scan returned an error instead of a complete result: result=$result " +
                    "lastError=${NativeEngine.getLastError()}",
                "",
                result.optString("error")
            )
            assertEquals(
                "$label scan returned an incomplete stream set: result=$result " +
                    "lastError=${NativeEngine.getLastError()}",
                expectedStreamCount,
                streams!!.length()
            )
        }
    }

    private fun nativeCrashLogLines(): Set<String> {
        val automation = InstrumentationRegistry.getInstrumentation().uiAutomation
        val descriptor = automation.executeShellCommand("logcat -d -v brief -t 500")
        return ParcelFileDescriptor.AutoCloseInputStream(descriptor).use { input ->
            input.bufferedReader(Charsets.UTF_8).useLines { lines ->
                lines.filter(::isNativeCrashLine).toSet()
            }
        }
    }

    private fun isNativeCrashLine(line: String): Boolean =
        line.contains("Fatal signal") ||
            line.contains("Abort message") ||
            line.contains("FATAL EXCEPTION")

    private class ConcurrentScan(private val session: Long) {
        private val executor: ExecutorService = newNamedExecutor("RTP-QA02-scan")
        private val progressReached = CountDownLatch(1)
        private val releaseScan = CountDownLatch(1)
        private val done = CountDownLatch(1)
        private val result = AtomicReference<String?>()
        private val failure = AtomicReference<Throwable?>()

        fun start() {
            executor.execute {
                try {
                    result.set(
                        NativeEngine.scanRtpStreams(
                            session,
                            SCAN_REQUEST,
                            NativeEngine.RtpProgressCallback { _, _ ->
                                progressReached.countDown()
                                try {
                                    releaseScan.await(20, TimeUnit.SECONDS)
                                } catch (interrupted: InterruptedException) {
                                    Thread.currentThread().interrupt()
                                    false
                                }
                            }
                        )
                    )
                } catch (throwable: Throwable) {
                    failure.set(throwable)
                } finally {
                    done.countDown()
                }
            }
        }

        fun awaitProgress(label: String) {
            assertTrue(
                "$label scan did not reach a concurrent progress point within 10s: " +
                    "lastError=${NativeEngine.getLastError()}",
                progressReached.await(10, TimeUnit.SECONDS)
            )
        }

        fun releaseAndAwait(label: String): JSONObject {
            releaseScan.countDown()
            assertTrue(
                "$label scan did not finish within 20s after releasing the overlap point: " +
                    "lastError=${NativeEngine.getLastError()}",
                done.await(20, TimeUnit.SECONDS)
            )
            executor.shutdownNow()
            executor.awaitTermination(5, TimeUnit.SECONDS)
            failure.get()?.let { throwable ->
                throw AssertionError(
                    "$label scan threw while running concurrently: " +
                        "lastError=${NativeEngine.getLastError()}",
                    throwable
                )
            }
            val json = result.get()
            assertNotNull(
                "$label scan returned null: lastError=${NativeEngine.getLastError()}",
                json
            )
            return JSONObject(json!!)
        }

        fun shutdown() {
            releaseScan.countDown()
            executor.shutdownNow()
            executor.awaitTermination(5, TimeUnit.SECONDS)
        }
    }

    companion object {
        private const val SCAN_REQUEST = "{\"limitToDisplayFilter\":false}"
        private const val PAGE_SIZE = 50
        private const val PAGING_ITERATIONS = 3

        private lateinit var appContext: Context
        private lateinit var testContext: Context
        private lateinit var captureFile: File

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
            captureFile = copyAssetFile(
                testContext,
                "rtp/sip_g711a_bidirectional.pcap",
                File(appContext.cacheDir, "rtp-concurrency-sip-g711a-bidirectional.pcap")
            )
        }

        @JvmStatic
        @AfterClass
        fun cleanupCapture() {
            if (::captureFile.isInitialized) {
                captureFile.delete()
            }
        }

        private fun copyAssetFolder(context: Context, assetPath: String, targetDir: File) {
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
                    copyAssetFile(context, childAssetPath, File(targetDir, child))
                } else {
                    copyAssetFolder(context, childAssetPath, File(targetDir, child))
                }
            }
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

        private fun newNamedExecutor(name: String): ExecutorService =
            Executors.newSingleThreadExecutor { runnable ->
                Thread(runnable, name).apply { isDaemon = true }
            }
    }
}