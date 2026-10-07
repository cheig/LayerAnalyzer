// Copyright (c) 2026 cheig
// LayerAnalyzer - https://github.com/cheig/LayerAnalyzer
// Licensed under GNU GPL version 3; see LICENSE.

package com.example.layanalyzer.viewmodel

import com.example.layanalyzer.ai.tools.AgentToolTestHarness
import com.example.layanalyzer.data.CaptureSessionCoordinator
import com.example.layanalyzer.data.PacketRepository
import com.example.layanalyzer.data.RtpMediaCache
import com.example.layanalyzer.data.RtpRepository
import com.example.layanalyzer.model.RtpContainerExportResult
import com.example.layanalyzer.model.RtpDecodeRequest
import com.example.layanalyzer.model.RtpDecodeResult
import com.example.layanalyzer.model.RtpExportFormat
import com.example.layanalyzer.model.RtpProgress
import com.example.layanalyzer.model.RtpRawExportResult
import com.example.layanalyzer.model.RtpRawOrder
import com.example.layanalyzer.model.RtpScanResult
import com.example.layanalyzer.model.RtpStream
import java.io.File
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Rule
import org.junit.Test
import org.junit.rules.TemporaryFolder

/**
 * RTP4-KT-03：容器导出（`.amr`/`.awb`/`.opus`）与「外部打开」准备的 ViewModel 单测。
 *
 * 用注入的 fake 仓库把「调了原生端点几次、用的什么 format」变成可观测的断言。
 *
 * **没有**断言的东西：真机上四种格式的端到端导出与外部打开 —— 那需要 AMR/Opus 抓包
 * 夹具（`app/src/androidTest/assets/rtp/` 里只有 G.711 与 SRTP 夹具，CONTRIBUTING.md
 * 禁止手造），归属 RTP4-QA-01；`androidTest` 的 `RtpContainerExportTest` 覆盖的是
 * 现有夹具真能验的 fail-closed 那一半。
 */
class RtpContainerExportViewModelTest {
    @get:Rule
    val temporaryFolder = TemporaryFolder()

    @Test
    fun `amr export calls the native endpoint with the format of the stream codec`() {
        val harness = harness("AMR")
        val copied = File(temporaryFolder.root, "copied.amr")

        harness.viewModel.exportFormat(
            stream = harness.streams().single(),
            format = RtpExportFormat.AMR,
            destination = RtpExportDestination("s0.amr") { source ->
                copied.writeBytes(source.readBytes())
            }
        )

        val state = harness.viewModel.exportState.value as RtpExportUiState.Finished
        assertEquals(listOf("s0.amr"), state.summary.files.map { it.displayName })
        assertEquals("audio/amr", state.summary.files.single().mimeType)
        assertTrue(state.summary.failures.isEmpty())
        // 原生端点只被调了一次，format 与该流的编码一致（AMR → "amr"）。
        assertEquals(listOf("s0" to "amr"), harness.repository.containerRequests)
        assertTrue(copied.isFile)
        // 缓存里的文件名由原生层按 `<streamId>.<ext>` 定（RTP4-NAT-06 冻结的契约），
        // 但必须落在同一个 RTP media cache 里。
        val exported = File(state.summary.files.single().filePath)
        assertTrue(exported.startsWith(harness.cacheRoot))
        assertEquals("s0.amr", exported.name)
    }

    @Test
    fun `amr-wb and opus map to their own native format and mime`() {
        val awb = harness("AMR-WB")
        awb.viewModel.exportContainer(
            streams = awb.streams(),
            format = RtpExportFormat.AWB,
            destinations = listOf(RtpExportDestination("s0.awb") { })
        )
        val awbState = awb.viewModel.exportState.value as RtpExportUiState.Finished
        assertEquals(listOf("s0" to "awb"), awb.repository.containerRequests)
        assertEquals("audio/amr-wb", awbState.summary.files.single().mimeType)

        val opus = harness("opus")
        opus.viewModel.shareContainer(
            streams = opus.streams(),
            format = RtpExportFormat.OPUS
        )
        val opusState = opus.viewModel.exportState.value as RtpExportUiState.Finished
        assertEquals(listOf("s0" to "opus"), opus.repository.containerRequests)
        assertEquals("audio/ogg", opusState.shareResults.single().mimeType)
    }

    @Test
    fun `a failed container export is recorded and leaves no half written file`() {
        val harness = harness("AMR")
        harness.repository.containerHandler = { _, _, _, outDir ->
            // 原生层「写失败只删半成品」之前先造一个半成品，Kotlin 侧必须把它清掉。
            File(outDir, "s0.amr").writeBytes(byteArrayOf(1, 2, 3))
            RtpContainerExportResult(
                path = "",
                format = "amr",
                frameCount = 0L,
                byteCount = 0L,
                error = "Unable to write the RTP container."
            )
        }
        val attempted = mutableListOf<String>()

        harness.viewModel.exportFormat(
            stream = harness.streams().single(),
            format = RtpExportFormat.AMR,
            destination = RtpExportDestination("s0.amr") { attempted += "s0" }
        )

        val state = harness.viewModel.exportState.value as RtpExportUiState.Finished
        assertTrue(attempted.isEmpty())
        assertEquals(listOf("s0"), state.summary.failures.map { it.streamId })
        assertEquals(
            "Unable to write the RTP container.",
            state.summary.failures.single().message
        )
        assertTrue(harness.cacheFiles().none { it.name.endsWith(".amr") })
    }

    @Test
    fun `a container format that does not match the codec never reaches the native endpoint`() {
        val harness = harness("g711A")

        harness.viewModel.exportContainer(
            streams = harness.streams(),
            format = RtpExportFormat.AMR,
            destinations = listOf(RtpExportDestination("s0.amr") { })
        )

        val state = harness.viewModel.exportState.value as RtpExportUiState.Finished
        assertEquals(listOf("s0"), state.summary.failures.map { it.streamId })
        assertTrue(state.summary.files.isEmpty())
        // fail-closed：G.711A 没有 AMR 容器，请求根本不发（原生层也会拒）。
        assertTrue(harness.repository.containerRequests.isEmpty())
    }

    @Test
    fun `a cancelled container export is a failure and leaves nothing behind`() {
        val harness = harness("opus")
        harness.repository.containerHandler = { _, _, _, _ ->
            RtpContainerExportResult(
                path = "",
                format = "opus",
                frameCount = 0L,
                byteCount = 0L,
                error = "",
                cancelled = true
            )
        }

        harness.viewModel.exportContainer(
            streams = harness.streams(),
            format = RtpExportFormat.OPUS,
            destinations = listOf(RtpExportDestination("s0.opus") { })
        )

        val state = harness.viewModel.exportState.value as RtpExportUiState.Finished
        assertEquals(listOf("s0"), state.summary.failures.map { it.streamId })
        assertTrue(harness.cacheFiles().none { it.name.endsWith(".opus") })
    }

    @Test
    fun `prepareExternalOpen exports a container for a container codec`() {
        val harness = harness("AMR")

        harness.viewModel.prepareExternalOpen(harness.streams().single())

        val state = harness.viewModel.externalOpenState.value as RtpExternalOpenUiState.Ready
        assertEquals("s0", state.streamId)
        assertEquals("audio/amr", state.mimeType)
        assertEquals(listOf("s0" to "amr"), harness.repository.containerRequests)
        val container = File(state.containerPath)
        assertTrue(container.isFile)
        assertEquals("amr", container.extension)
        assertTrue(container.startsWith(harness.cacheRoot))
    }

    @Test
    fun `prepareExternalOpen skips the native endpoint for a codec without a container`() {
        val harness = harness("g711A")

        harness.viewModel.prepareExternalOpen(harness.streams().single())

        val state = harness.viewModel.externalOpenState.value as RtpExternalOpenUiState.Ready
        assertEquals("s0", state.streamId)
        // 容器路径为空 = 调用方直接用 WAV 打开，不经过原生容器端点。
        assertEquals("", state.containerPath)
        assertEquals("", state.mimeType)
        assertTrue(harness.repository.containerRequests.isEmpty())
    }

    @Test
    fun `prepareExternalOpen reports an export failure instead of silently using the wav`() {
        val harness = harness("opus")
        harness.repository.containerHandler = { _, _, _, _ ->
            RtpContainerExportResult("", "opus", 0L, 0L, "nativeDecode")
        }

        harness.viewModel.prepareExternalOpen(harness.streams().single())

        val state = harness.viewModel.externalOpenState.value as RtpExternalOpenUiState.Error
        assertEquals("nativeDecode", state.message)
    }

    @Test
    fun `container export needs a scan like the other export kinds`() {
        val harness = harness("AMR", scan = false)

        harness.viewModel.exportContainer(
            streams = emptyList(),
            format = RtpExportFormat.AMR,
            destinations = emptyList()
        )

        assertTrue(harness.viewModel.exportState.value is RtpExportUiState.Error)
        assertTrue(harness.repository.containerRequests.isEmpty())
    }

    private class Harness(
        val viewModel: RtpViewModel,
        val repository: FakeRtpRepository,
        val cacheRoot: File
    ) {
        fun streams(): List<RtpStream> =
            (viewModel.state.value as RtpScanUiState.Done).result.streams

        fun cacheFiles(): List<File> = cacheRoot.walkTopDown().filter { it.isFile }.toList()
    }

    private fun harness(codec: String, scan: Boolean = true): Harness {
        val cacheRoot = File(temporaryFolder.root, "rtp-$codec-${System.nanoTime()}")
        val cache = RtpMediaCache(cacheRoot)
        val repository = FakeRtpRepository().apply { scanResult = scanResult("s0", codec) }
        val file = temporaryFolder.newFile("capture-${System.nanoTime()}.pcap")
        val source = AgentToolTestHarness.FakeSource(10)
        source.switchSession(SESSION_HANDLE, file)
        val coordinator = CaptureSessionCoordinator(
            dataSource = source,
            fingerprintDispatcher = Dispatchers.Unconfined,
            nativeDispatcher = Dispatchers.Unconfined
        )
        coordinator.onSessionOpened(checkNotNull(source.currentFile()))
        val viewModel = RtpViewModel(
            repository = repository,
            sessionCoordinator = coordinator,
            ioDispatcher = Dispatchers.Unconfined,
            externalScope = CoroutineScope(Dispatchers.Unconfined),
            mediaCache = cache,
            cacheRoot = cacheRoot
        )
        if (scan) viewModel.scan()
        return Harness(viewModel, repository, cacheRoot)
    }

    private class FakeRtpRepository : RtpRepository(PacketRepository()) {
        var scanResult: RtpScanResult = scanResult("s0", "g711A")
        var containerHandler: (Long, String, String, File) -> RtpContainerExportResult =
            { _, streamId, format, outDir ->
                val extension = when (format) {
                    "awb" -> "awb"
                    "opus" -> "opus"
                    else -> "amr"
                }
                val file = File(outDir, "$streamId.$extension")
                file.writeBytes(byteArrayOf(0x23, 0x21, 0x41, 0x4D, 0x52))
                RtpContainerExportResult(
                    path = file.absolutePath,
                    format = format,
                    frameCount = 10L,
                    byteCount = 5L,
                    error = ""
                )
            }

        val containerRequests = mutableListOf<Pair<String, String>>()

        override fun scanRtpStreams(
            limitToDisplayFilter: Boolean,
            onProgress: ((RtpProgress) -> Boolean)?
        ): RtpScanResult = scanResult

        override fun decodeAudio(
            request: RtpDecodeRequest,
            outDir: File,
            onProgress: ((RtpProgress) -> Boolean)?
        ): RtpDecodeResult = RtpDecodeResult("", false, emptyList(), emptyList())

        override fun exportRaw(
            scanGeneration: Long,
            streamId: String,
            order: RtpRawOrder,
            outFile: File
        ): RtpRawExportResult = RtpRawExportResult(0L, 0L, "not used")

        override fun exportContainer(
            scanGeneration: Long,
            streamId: String,
            format: String,
            outDir: File
        ): RtpContainerExportResult {
            containerRequests += streamId to format
            return containerHandler(scanGeneration, streamId, format, outDir)
        }
    }

    private companion object {
        const val SESSION_HANDLE = 1L
    }
}

/**
 * 一条流的扫描结果夹具（字段口径与 `RtpExportTest` 里的同名字段一致：一条流、可解码）。
 */
private fun scanResult(id: String, codec: String): RtpScanResult {
    val stream = """
        {
          "id":"$id", "src":"10.0.0.1", "srcPort":40000,
          "dst":"10.0.0.2", "dstPort":30000, "ssrc":1,
          "ssrcHex":"0x00000001", "pt":97, "codec":"$codec",
          "codecSource":"sdp", "clockRate":8000, "decodable":"yes"
        }
        """.trimIndent()
    return RtpRepository(PacketRepository()).parseScanResult(
        """
        {
          "schemaVersion":1, "error":"", "cancelled":false,
          "scanGeneration":7, "framesScanned":10, "heuristicEnabled":false,
          "streamsTruncated":false, "streams":[$stream]
        }
        """.trimIndent()
    )
}
