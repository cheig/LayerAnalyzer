package com.example.layanalyzer

import android.content.Context
import androidx.test.core.app.ApplicationProvider
import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.platform.app.InstrumentationRegistry
import com.example.layanalyzer.data.PacketRepository
import com.example.layanalyzer.data.RtpRepository
import com.example.layanalyzer.model.RtpCodecCatalog
import com.example.layanalyzer.model.RtpExportFormat
import com.example.layanalyzer.model.RtpScanResult
import kotlinx.coroutines.flow.first
import kotlinx.coroutines.runBlocking
import kotlinx.coroutines.withTimeout
import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.BeforeClass
import org.junit.Test
import org.junit.runner.RunWith
import java.io.File

/**
 * RTP4-KT-03: `RtpRepository.exportContainer` (the Kotlin entry the export format
 * menu uses) against the capture fixtures that actually exist, plus the
 * "codec → available formats" table applied to a real scan.
 *
 * WHAT IS NOT TESTED HERE, AND WHY
 * ================================
 * The card's acceptance for this task -- "export all four formats by hand and
 * open each one externally" -- is a manual, on-device gesture: it needs a human
 * who can tap the format dialog, pick a SAF destination, and see the system
 * chooser. Nothing in this file pretends to do that.
 *
 * The half that *can* be automated here is what the checked-in fixtures support:
 * the fail-closed envelope of the container endpoint as the Kotlin repository
 * exposes it (a rejected request answers `error` and leaves no file behind), and
 * the format table read off a real scanned stream.
 *
 * The end-to-end half -- an AMR/AMR-WB/Opus stream exported to `.amr`/`.awb`/
 * `.opus` with `path` existing, `format` matching the codec and `byteCount > 0`,
 * plus the "format does not match the stream codec." rejection -- needs an
 * AMR-NB, an AMR-WB and an Opus capture. **None exists under
 * `app/src/androidTest/assets/rtp/`** (see CONTRIBUTING.md; `sip_g711a_bidirectional`,
 * `g711u_loss_reorder`, `rtp_no_signal` and `srtp` are all natively decoded or
 * rejected codecs), so those assertions are deliberately absent rather than
 * softened into something that always passes. Creating that fixture is
 * RTP4-QA-01's deliverable, and CONTRIBUTING.md forbids hand-editing
 * fixtures.
 */
@RunWith(AndroidJUnit4::class)
class RtpContainerExportTest {

    @Test(timeout = 120_000)
    fun formatTableIsReadOffARealScannedStream() {
        openCapture(TARGET_SAMPLE).use { capture ->
            val scan = capture.repository.scanRtpStreams()
            assertEquals("", scan.error)
            val stream = findG711AStream(scan)

            // G.711A 是原生解码的编码：WAV 与裸流两种格式，没有容器。
            assertEquals(
                setOf(RtpExportFormat.WAV, RtpExportFormat.RAW),
                RtpCodecCatalog.exportFormats(stream.codec)
            )
            assertNull(RtpCodecCatalog.containerFormat(stream.codec))
            assertEquals(
                "audio/wav",
                RtpCodecCatalog.exportFormats(stream.codec)
                    .first { it == RtpExportFormat.WAV }
                    .mimeType
            )
            assertEquals(
                "application/octet-stream",
                RtpCodecCatalog.exportFormats(stream.codec)
                    .first { it == RtpExportFormat.RAW }
                    .mimeType
            )
        }
    }

    @Test(timeout = 120_000)
    fun aFormatOutsideTheThreeIsRejectedWithoutOpeningAFile() {
        openCapture(TARGET_SAMPLE).use { capture ->
            val scan = capture.repository.scanRtpStreams()
            val stream = findG711AStream(scan)
            val outDir = requestDir("bad-format")
            outDir.deleteRecursively()

            val bad = capture.repository.exportContainer(
                scanGeneration = scan.scanGeneration,
                streamId = stream.id,
                format = "wav",
                outDir = outDir
            )
            assertEquals("format must be amr, awb or opus.", bad.error)
            assertEquals("", bad.path)
            assertEquals(0L, bad.byteCount)
            assertFalse(bad.cancelled)
            assertFalse(bad.isSuccess)
            assertNoOutputFiles(outDir)
        }
    }

    @Test(timeout = 120_000)
    fun aNativeDecodeCodecIsRoutedAwayBeforeAnyFileIsWritten() {
        openCapture(TARGET_SAMPLE).use { capture ->
            val scan = capture.repository.scanRtpStreams()
            val stream = findG711AStream(scan)
            val outDir = requestDir("native-decode")
            outDir.deleteRecursively()

            val result = capture.repository.exportContainer(
                scanGeneration = scan.scanGeneration,
                streamId = stream.id,
                format = "amr",
                outDir = outDir
            )
            // G.711A 归 `decodeRtpAudio` 管，不属于容器端点 —— 拒绝必须来自编码 id，
            // 而不是文件已经打开之后才失败（这正是格式表与原生集合必须一致的原因）。
            assertEquals("nativeDecode", result.error)
            assertFalse(result.cancelled)
            assertEquals("", result.path)
            assertNoOutputFiles(outDir)
        }
    }

    @Test(timeout = 120_000)
    fun aStaleScanGenerationIsRejected() {
        openCapture(TARGET_SAMPLE).use { capture ->
            val scan = capture.repository.scanRtpStreams()
            val stream = findG711AStream(scan)
            val outDir = requestDir("stale")
            outDir.deleteRecursively()

            val result = capture.repository.exportContainer(
                scanGeneration = scan.scanGeneration + 1,
                streamId = stream.id,
                format = "amr",
                outDir = outDir
            )
            assertEquals("staleScan", result.error)
            assertFalse(result.cancelled)
            assertNoOutputFiles(outDir)
        }
    }

    @Test(timeout = 60_000)
    fun withoutAnOpenCaptureTheRepositoryAnswersBeforeAnyJniCall() {
        val repository = RtpRepository(PacketRepository())
        val result = repository.exportContainer(
            scanGeneration = 1L,
            streamId = "s0",
            format = "amr",
            outDir = requestDir("no-session")
        )
        assertEquals("No capture is open.", result.error)
        assertEquals("", result.path)
        assertFalse(result.isSuccess)
    }

    private fun openCapture(sampleName: String): OpenCapture {
        val capture = copyAssetFile(
            testContext,
            "rtp/$sampleName.pcap",
            File(appContext.cacheDir, "rtp-container-$sampleName.pcap")
        )
        val packetRepository = PacketRepository()
        val opened = packetRepository.openFile(capture.absolutePath)
        assertTrue(
            "openFile failed: ${opened.exceptionOrNull()?.message}",
            opened.isSuccess
        )
        return OpenCapture(packetRepository)
    }

    /** 一次打开的抓包：仓库 + 关闭入口（`closeFile` 在 `PacketRepository` 上）。 */
    private class OpenCapture(private val packetRepository: PacketRepository) :
        AutoCloseable {
        val repository = RtpRepository(packetRepository)

        override fun close() {
            packetRepository.closeFile()
        }
    }

    private fun findG711AStream(scan: RtpScanResult) =
        scan.streams.firstOrNull { it.ssrc == TARGET_SSRC && it.codec == "g711A" }
            ?: throw AssertionError("No decodable g711A SSRC=$TARGET_SSRC stream: $scan")

    private fun assertNoOutputFiles(outDir: File) {
        assertTrue(
            "a rejected container request left output behind: " +
                outDir.listFiles().orEmpty().joinToString(),
            !outDir.exists() || outDir.listFiles().orEmpty().isEmpty()
        )
    }

    private fun requestDir(name: String): File =
        File(appContext.cacheDir, "rtp-container-$name")

    @After
    fun cleanOutputs() {
        appContext.cacheDir.listFiles()
            .orEmpty()
            .filter { it.name.startsWith("rtp-container-") }
            .forEach(File::deleteRecursively)
    }

    companion object {
        private const val TARGET_SAMPLE = "sip_g711a_bidirectional"
        private const val TARGET_SSRC = 2591773570L

        private lateinit var appContext: Context
        private lateinit var testContext: Context

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
                    copyAssetFile(context, childAssetPath, File(targetDir, child))
                } else {
                    copyAssetFolder(context, childAssetPath, File(targetDir, child))
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
