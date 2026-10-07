// Copyright (c) 2026 cheig
// LayerAnalyzer - https://github.com/cheig/LayerAnalyzer
// Licensed under GNU GPL version 3; see LICENSE.

package com.example.layanalyzer.viewmodel

import com.example.layanalyzer.ai.tools.AgentToolTestHarness
import com.example.layanalyzer.data.CaptureSessionCoordinator
import com.example.layanalyzer.data.PacketRepository
import com.example.layanalyzer.data.RtpMediaCache
import com.example.layanalyzer.data.RtpRepository
import com.example.layanalyzer.model.RtpDecodeRequest
import com.example.layanalyzer.model.RtpDecodeResult
import com.example.layanalyzer.model.RtpDecodeStats
import com.example.layanalyzer.model.RtpDecodedItem
import com.example.layanalyzer.model.RtpProgress
import com.example.layanalyzer.model.RtpRawExportResult
import com.example.layanalyzer.model.RtpRawOrder
import com.example.layanalyzer.model.RtpScanResult
import com.example.layanalyzer.model.RtpStream
import com.example.layanalyzer.model.RtpUnsupportedStream
import java.io.File
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Rule
import org.junit.Test
import org.junit.rules.TemporaryFolder

class RtpExportTest {
    @get:Rule
    val temporaryFolder = TemporaryFolder()

    @Test
    fun `wav export renders all streams and continues after a destination failure`() {
        val cacheRoot = File(temporaryFolder.root, "rtp")
        val cache = RtpMediaCache(cacheRoot)
        val repository = FakeRtpRepository().apply {
            scanResult = buildScanResult("s0", "s1")
            decodeHandler = { request, outDir ->
                request.streamIds.map { streamId ->
                    val file = outDir.resolve("$streamId.wav")
                    file.writeBytes(byteArrayOf(1, 2, 3))
                    buildDecodedItem(streamId, file)
                }.let { items ->
                    RtpDecodeResult("", false, items, emptyList())
                }
            }
        }
        val viewModel = viewModel(repository, cacheRoot, cache)
        viewModel.scan()
        val streams = scanStreams(viewModel)
        val copied = File(temporaryFolder.root, "copied.wav")
        val attempted = mutableListOf<String>()

        viewModel.exportWav(
            streams = streams,
            destinations = listOf(
                RtpExportDestination("s0.wav") {
                    attempted += "s0"
                    error("copy failed")
                },
                RtpExportDestination("s1.wav") { source ->
                    attempted += "s1"
                    copied.writeBytes(source.readBytes())
                }
            )
        )

        val state = viewModel.exportState.value as RtpExportUiState.Finished
        assertEquals(listOf("s0", "s1"), attempted)
        assertEquals(listOf("s1.wav"), state.summary.files.map { it.displayName })
        assertEquals(listOf("s0"), state.summary.failures.map { it.streamId })
        assertTrue(copied.isFile)
        assertEquals(
            listOf(listOf("s0"), listOf("s1")),
            repository.decodeRequests.map { it.streamIds }
        )
    }

    @Test
    fun `wav export continues after the first decode fails and shares the successful stream`() {
        val cacheRoot = File(temporaryFolder.root, "rtp")
        val cache = RtpMediaCache(cacheRoot)
        val repository = FakeRtpRepository().apply {
            scanResult = buildScanResult("s0", "s1")
            decodeHandler = { request, outDir ->
                if (request.streamIds == listOf("s0")) {
                    RtpDecodeResult(
                        error = "decode failed",
                        cancelled = false,
                        items = emptyList(),
                        unsupported = emptyList()
                    )
                } else {
                    val file = outDir.resolve("s1.wav")
                    file.writeBytes(byteArrayOf(1))
                    RtpDecodeResult("", false, listOf(buildDecodedItem("s1", file)), emptyList())
                }
            }
        }
        val viewModel = viewModel(repository, cacheRoot, cache)
        viewModel.scan()
        val attempted = mutableListOf<String>()

        viewModel.exportWav(
            streams = scanStreams(viewModel),
            destinations = listOf(
                RtpExportDestination("s0.wav") { attempted += "s0" },
                RtpExportDestination("s1.wav") { attempted += "s1" }
            )
        )

        val exportState = viewModel.exportState.value as RtpExportUiState.Finished
        assertEquals(listOf("s1"), attempted)
        assertEquals(listOf("s1.wav"), exportState.summary.files.map { it.displayName })
        assertEquals(listOf("s0"), exportState.summary.failures.map { it.streamId })
        val exportedPath = exportState.summary.files.single().filePath

        viewModel.clearExportState()
        viewModel.shareWav(scanStreams(viewModel))

        val shareState = viewModel.exportState.value as RtpExportUiState.Finished
        assertEquals(1, shareState.shareResults.size)
        assertTrue(File(shareState.shareResults.single().filePath).isFile)
        assertEquals(exportedPath, shareState.shareResults.single().filePath)
        assertEquals("audio/wav", shareState.shareResults.single().mimeType)
        assertEquals(listOf("s0"), shareState.summary.failures.map { it.streamId })
        assertEquals(
            listOf(listOf("s0"), listOf("s1"), listOf("s0")),
            repository.decodeRequests.map { it.streamIds }
        )
    }

    @Test
    fun `raw export skips an unsupported codec but exports the remaining stream`() {
        val cacheRoot = File(temporaryFolder.root, "rtp")
        val cache = RtpMediaCache(cacheRoot)
        val repository = FakeRtpRepository().apply {
            scanResult = buildScanResult("s0", "s1", codecs = listOf("g711A", "opus"))
            rawHandler = { streamId, outFile ->
                outFile.writeBytes(byteArrayOf(streamId.last().code.toByte()))
                RtpRawExportResult(bytes = 1L, packets = 1L, error = "")
            }
        }
        val viewModel = viewModel(repository, cacheRoot, cache)
        viewModel.scan()
        val streams = scanStreams(viewModel)
        val copied = File(temporaryFolder.root, "copied.pcma")

        viewModel.exportRaw(
            streams = streams,
            destinations = listOf(
                RtpExportDestination("s0.pcma") { source ->
                    copied.writeBytes(source.readBytes())
                },
                RtpExportDestination("s1.opus") {
                    error("unsupported destination should not be written")
                }
            ),
            order = RtpRawOrder.ARRIVAL
        )

        val state = viewModel.exportState.value as RtpExportUiState.Finished
        assertEquals(listOf("s0.pcma"), state.summary.files.map { it.displayName })
        assertEquals(listOf("s1"), state.summary.failures.map { it.streamId })
        assertEquals(listOf("s0"), repository.rawRequests.map { it.first })
        assertEquals(listOf(RtpRawOrder.ARRIVAL), repository.rawRequests.map { it.second })
        assertTrue(copied.isFile)
    }

    @Test
    fun `wav export records an unsupported stream once and still exports the other`() {
        val cacheRoot = File(temporaryFolder.root, "rtp")
        val cache = RtpMediaCache(cacheRoot)
        val repository = FakeRtpRepository().apply {
            scanResult = buildScanResult("s0", "s1")
            decodeHandler = { _, outDir ->
                val file = outDir.resolve("s1.wav")
                file.writeBytes(byteArrayOf(1))
                RtpDecodeResult(
                    error = "",
                    cancelled = false,
                    items = listOf(buildDecodedItem("s1", file)),
                    unsupported = listOf(RtpUnsupportedStream("s0", "unsupported"))
                )
            }
        }
        val viewModel = viewModel(repository, cacheRoot, cache)
        viewModel.scan()
        val attempted = mutableListOf<String>()

        viewModel.exportWav(
            streams = scanStreams(viewModel),
            destinations = listOf(
                RtpExportDestination("s0.wav") { attempted += "s0" },
                RtpExportDestination("s1.wav") { attempted += "s1" }
            )
        )

        val state = viewModel.exportState.value as RtpExportUiState.Finished
        assertEquals(listOf("s1"), attempted)
        assertEquals(listOf("s0"), state.summary.failures.map { it.streamId })
        assertEquals("unsupported", state.summary.failures.single().message)
    }

    @Test
    fun `share action publishes cached files without a SAF destination`() {
        val cacheRoot = File(temporaryFolder.root, "rtp")
        val cache = RtpMediaCache(cacheRoot)
        val repository = FakeRtpRepository().apply {
            scanResult = buildScanResult("s0")
            decodeHandler = { _, outDir ->
                val file = outDir.resolve("s0.wav")
                file.writeBytes(byteArrayOf(1))
                RtpDecodeResult("", false, listOf(buildDecodedItem("s0", file)), emptyList())
            }
        }
        val viewModel = viewModel(repository, cacheRoot, cache)
        viewModel.scan()

        viewModel.shareWav(scanStreams(viewModel))

        val state = viewModel.exportState.value as RtpExportUiState.Finished
        assertEquals(1, state.shareResults.size)
        assertEquals("audio/wav", state.shareResults.single().mimeType)
        assertTrue(File(state.shareResults.single().filePath).isFile)
    }

    private fun viewModel(
        repository: RtpRepository,
        cacheRoot: File,
        cache: RtpMediaCache
    ): RtpViewModel {
        val file = temporaryFolder.newFile("capture-${System.nanoTime()}.pcap")
        val source = AgentToolTestHarness.FakeSource(10)
        source.switchSession(SESSION_HANDLE, file)
        val coordinator = CaptureSessionCoordinator(
            dataSource = source,
            fingerprintDispatcher = Dispatchers.Unconfined,
            nativeDispatcher = Dispatchers.Unconfined
        )
        coordinator.onSessionOpened(checkNotNull(source.currentFile()))
        return RtpViewModel(
            repository = repository,
            sessionCoordinator = coordinator,
            ioDispatcher = Dispatchers.Unconfined,
            externalScope = CoroutineScope(Dispatchers.Unconfined),
            mediaCache = cache,
            cacheRoot = cacheRoot
        )
    }

    private fun scanStreams(viewModel: RtpViewModel): List<RtpStream> =
        (viewModel.state.value as RtpScanUiState.Done).result.streams

    private class FakeRtpRepository : RtpRepository(PacketRepository()) {
        var scanResult: RtpScanResult = buildScanResult("s0")
        var decodeHandler: (RtpDecodeRequest, File) -> RtpDecodeResult =
            { _, _ -> RtpDecodeResult("", false, emptyList(), emptyList()) }
        var rawHandler: (String, File) -> RtpRawExportResult =
            { _, _ -> RtpRawExportResult(0L, 0L, "") }

        val decodeRequests = mutableListOf<RtpDecodeRequest>()
        val rawRequests = mutableListOf<Pair<String, RtpRawOrder>>()

        override fun scanRtpStreams(
            limitToDisplayFilter: Boolean,
            onProgress: ((RtpProgress) -> Boolean)?
        ): RtpScanResult = scanResult

        override fun decodeAudio(
            request: RtpDecodeRequest,
            outDir: File,
            onProgress: ((RtpProgress) -> Boolean)?
        ): RtpDecodeResult {
            decodeRequests += request
            return decodeHandler(request, outDir)
        }

        override fun exportRaw(
            scanGeneration: Long,
            streamId: String,
            order: RtpRawOrder,
            outFile: File
        ): RtpRawExportResult {
            rawRequests += streamId to order
            return rawHandler(streamId, outFile)
        }
    }

    private companion object {
        const val SESSION_HANDLE = 1L
    }
}

private fun buildScanResult(
    vararg ids: String,
    codecs: List<String> = ids.map { "g711A" }
): RtpScanResult {
    val streams = ids.mapIndexed { index, id ->
        """
        {
          "id":"$id", "src":"10.0.0.${index + 1}", "srcPort":${40_000 + index},
          "dst":"10.0.0.2", "dstPort":30000, "ssrc":${index + 1},
          "ssrcHex":"0x0000000${index + 1}", "pt":8, "codec":"${codecs[index]}",
          "codecSource":"static", "clockRate":8000, "decodable":"yes"
        }
        """.trimIndent()
    }.joinToString(",")
    return RtpRepository(PacketRepository()).parseScanResult(
        """
        {
          "schemaVersion":1, "error":"", "cancelled":false,
          "scanGeneration":7, "framesScanned":10, "heuristicEnabled":false,
          "streamsTruncated":false, "streams":[$streams]
        }
        """.trimIndent()
    )
}

private fun buildDecodedItem(streamId: String, file: File): RtpDecodedItem = RtpDecodedItem(
    streamId = streamId,
    codec = "g711A",
    sampleRate = 8_000,
    channels = 1,
    wavPath = file.absolutePath,
    peaksPath = "",
    mapPath = "",
    durationMs = 20L,
    startRel = 0.0,
    startAbsEpochMs = 0L,
    gaps = emptyList(),
    events = emptyList(),
    stats = RtpDecodeStats(1L, 0L, 0L, 0L, 0L)
)
