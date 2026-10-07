package com.example.layanalyzer.viewmodel

import com.example.layanalyzer.ai.tools.AgentToolTestHarness
import com.example.layanalyzer.data.CaptureSessionCoordinator
import com.example.layanalyzer.data.PacketRepository
import com.example.layanalyzer.data.RtpMediaCache
import com.example.layanalyzer.data.RtpRepository
import com.example.layanalyzer.media.PlayerFacade
import com.example.layanalyzer.media.RtpAudioPlayerController
import com.example.layanalyzer.media.RtpPlayerState
import com.example.layanalyzer.model.RtpDecodeRequest
import com.example.layanalyzer.model.RtpDecodeResult
import com.example.layanalyzer.model.RtpDecodeStats
import com.example.layanalyzer.model.RtpDecodedItem
import com.example.layanalyzer.model.RtpProgress
import com.example.layanalyzer.model.RtpScanResult
import com.example.layanalyzer.model.RtpTimingMode
import java.io.File
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Rule
import org.junit.Test
import org.junit.rules.TemporaryFolder

class RtpPlayerViewModelTest {
    @get:Rule
    val temporaryFolder = TemporaryFolder()

    @Test
    fun `opening a stream decodes it and publishes a ready player state`() {
        val harness = Harness(temporaryFolder)

        harness.viewModel.scan()
        harness.viewModel.openPlayerStream(harness.stream())

        val state = harness.viewModel.playerState.value
        assertTrue(state.isOpen)
        assertEquals(RtpPlayerDecodeStatus.READY, state.status)
        assertEquals("s0", state.selectedStream?.id)
        assertEquals("s0", state.selectedItem?.streamId)
        assertEquals(listOf(listOf("s0")), harness.repository.decodeRequests.map { it.streamIds })
        assertTrue(File(state.selectedItem!!.wavPath).isFile)
        assertEquals(RtpPlayerState.Preparing, harness.viewModel.playerPlaybackState.value)

        harness.playerFacade.onPrepared?.invoke()
        assertEquals(RtpPlayerState.Playing, harness.viewModel.playerPlaybackState.value)
        assertEquals(1, harness.playerFacade.startCalls)
        harness.viewModel.closePlayer()
    }

    @Test
    fun `opening without auto play stays paused through decoding and retry until play is requested`() {
        val harness = Harness(temporaryFolder)
        harness.viewModel.scan()

        harness.viewModel.openPlayer(listOf(harness.stream()), autoPlay = false)
        harness.playerFacade.onPrepared?.invoke()

        val state = harness.viewModel.playerState.value
        assertTrue(state.isOpen)
        assertEquals("s0", state.selectedStream?.id)
        assertEquals(RtpPlayerDecodeStatus.READY, state.status)
        assertEquals(RtpPlayerState.Paused, harness.viewModel.playerPlaybackState.value)
        assertEquals(0, harness.playerFacade.startCalls)

        harness.viewModel.retryPlayerDecode()
        harness.playerFacade.onPrepared?.invoke()
        assertEquals(RtpPlayerState.Paused, harness.viewModel.playerPlaybackState.value)
        assertEquals(0, harness.playerFacade.startCalls)

        harness.viewModel.playPlayer()
        assertEquals(RtpPlayerState.Playing, harness.viewModel.playerPlaybackState.value)
        assertEquals(1, harness.playerFacade.startCalls)
        harness.viewModel.closePlayer()
    }

    @Test
    fun `changing timing deletes the old request directory and decodes again`() {
        val harness = Harness(temporaryFolder)
        harness.viewModel.scan()
        harness.viewModel.openPlayerStream(harness.stream())
        val firstDirectory = checkNotNull(
            File(harness.viewModel.playerState.value.selectedItem!!.wavPath).parentFile
        )
        assertTrue(firstDirectory.isDirectory)

        harness.viewModel.setPlayerTiming(RtpTimingMode.RTP_TIMESTAMP)

        assertFalse(firstDirectory.exists())
        assertEquals(
            listOf(RtpTimingMode.JITTER, RtpTimingMode.RTP_TIMESTAMP),
            harness.repository.decodeRequests.map { it.timing }
        )
        assertEquals(RtpPlayerDecodeStatus.READY, harness.viewModel.playerState.value.status)
    }

    @Test
    fun `cancelling a player request clears its cached output`() {
        val harness = Harness(temporaryFolder)
        harness.viewModel.scan()
        harness.viewModel.openPlayerStream(harness.stream())
        val requestDirectory = checkNotNull(
            File(harness.viewModel.playerState.value.selectedItem!!.wavPath).parentFile
        )

        harness.viewModel.cancelPlayerDecode()

        assertEquals(RtpPlayerDecodeStatus.CANCELLED, harness.viewModel.playerState.value.status)
        assertFalse(requestDirectory.exists())
        assertTrue(harness.viewModel.playerState.value.selectedItem == null)
    }

    @Test
    fun `session invalidation closes the player`() {
        val harness = Harness(temporaryFolder)
        harness.viewModel.scan()
        harness.viewModel.openPlayerStream(harness.stream())
        assertTrue(harness.viewModel.playerState.value.isOpen)

        harness.coordinator.invalidateSession()

        assertFalse(harness.viewModel.playerState.value.isOpen)
        assertEquals(RtpPlayerDecodeStatus.IDLE, harness.viewModel.playerState.value.status)
    }

    private class Harness(temporaryFolder: TemporaryFolder) {
        val cacheRoot = File(temporaryFolder.root, "rtp")
        val cache = RtpMediaCache(cacheRoot)
        val repository = FakePlayerRepository()
        val coordinator: CaptureSessionCoordinator
        val playerFacade = FakePlayerFacade()
        val viewModel: RtpViewModel

        init {
            val file = temporaryFolder.newFile("capture-${System.nanoTime()}.pcap")
            val source = AgentToolTestHarness.FakeSource(10)
            source.switchSession(SESSION_HANDLE, file)
            coordinator = CaptureSessionCoordinator(
                dataSource = source,
                fingerprintDispatcher = Dispatchers.Unconfined,
                nativeDispatcher = Dispatchers.Unconfined
            )
            coordinator.onSessionOpened(checkNotNull(source.currentFile()))
            repository.scanResult = scanResult()
            viewModel = RtpViewModel(
                repository = repository,
                sessionCoordinator = coordinator,
                ioDispatcher = Dispatchers.Unconfined,
                externalScope = CoroutineScope(Dispatchers.Unconfined),
                audioPlayerController = RtpAudioPlayerController(
                    facade = playerFacade,
                    scope = CoroutineScope(Dispatchers.Unconfined),
                    tickMillis = 10_000L
                ),
                mediaCache = cache,
                cacheRoot = cacheRoot
            )
        }

        fun stream() =
            (viewModel.state.value as RtpScanUiState.Done).result.streams.single()
    }

    private class FakePlayerRepository : RtpRepository(PacketRepository()) {
        var scanResult: RtpScanResult = scanResult()
        val decodeRequests = mutableListOf<RtpDecodeRequest>()

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
            val wav = File(outDir, "s0.wav").apply { writeBytes(byteArrayOf(1, 2, 3)) }
            File(outDir, "s0.peaks").writeBytes(ByteArray(16))
            File(outDir, "s0.map").writeBytes(ByteArray(8))
            onProgress?.invoke(RtpProgress(100, 100))
            return RtpDecodeResult(
                error = "",
                cancelled = false,
                items = listOf(
                    RtpDecodedItem(
                        streamId = "s0",
                        codec = "g711A",
                        sampleRate = 8_000,
                        channels = 1,
                        wavPath = wav.absolutePath,
                        peaksPath = File(outDir, "s0.peaks").absolutePath,
                        mapPath = File(outDir, "s0.map").absolutePath,
                        durationMs = 1_000L,
                        startRel = 0.0,
                        startAbsEpochMs = 0L,
                        gaps = emptyList(),
                        events = emptyList(),
                        stats = RtpDecodeStats(50L, 1L, 2L, 3L, 0L)
                    )
                ),
                unsupported = emptyList()
            )
        }
    }

    private class FakePlayerFacade : PlayerFacade {
        var startCalls = 0
        override var onPrepared: (() -> Unit)? = null
        override var onCompletion: (() -> Unit)? = null
        override var onError: ((String) -> Unit)? = null
        override var durationMs: Long = 1_000L
        override val positionMs: Long = 0L
        override val isPlaying: Boolean = false

        override fun setDataSource(path: String) = Unit
        override fun prepareAsync() = Unit
        override fun start() {
            startCalls += 1
        }
        override fun pause() = Unit
        override fun seekTo(ms: Long) = Unit
        override fun release() = Unit
        override fun setVolume(left: Float, right: Float) = Unit
    }

    private companion object {
        const val SESSION_HANDLE = 1L
    }
}

private fun scanResult(): RtpScanResult =
    RtpRepository(PacketRepository()).parseScanResult(
        """
        {
          "schemaVersion":1, "error":"", "cancelled":false,
          "scanGeneration":7, "framesScanned":10, "heuristicEnabled":false,
          "streamsTruncated":false,
          "streams":[{
            "id":"s0", "src":"10.0.0.1", "srcPort":40000,
            "dst":"10.0.0.2", "dstPort":30000, "ssrc":1,
            "ssrcHex":"0x00000001", "pt":8, "codec":"g711A",
            "codecSource":"static", "clockRate":8000, "decodable":"yes"
          }]
        }
        """.trimIndent()
    )
