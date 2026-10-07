package com.example.layanalyzer.viewmodel

import com.example.layanalyzer.ai.tools.AgentToolTestHarness
import com.example.layanalyzer.data.CaptureSessionCoordinator
import com.example.layanalyzer.data.LinkedRtpStream
import com.example.layanalyzer.data.PacketRepository
import com.example.layanalyzer.data.RtpLinkReason
import com.example.layanalyzer.data.RtpMediaCache
import com.example.layanalyzer.data.RtpRepository
import com.example.layanalyzer.data.RtpStreamDirection
import com.example.layanalyzer.data.VideoParamSets
import com.example.layanalyzer.data.VoipCall
import com.example.layanalyzer.data.VoipCallState
import com.example.layanalyzer.media.AacEncoderProbe
import com.example.layanalyzer.media.AacExportResult
import com.example.layanalyzer.media.AacTrackExporter
import com.example.layanalyzer.media.AudioVideoMuxer
import com.example.layanalyzer.media.AvMuxResult
import com.example.layanalyzer.media.RtpAvMuxAvailability
import com.example.layanalyzer.media.VideoMuxFormat
import com.example.layanalyzer.model.RtpDecodeRequest
import com.example.layanalyzer.model.RtpDecodeResult
import com.example.layanalyzer.model.RtpDecodeStats
import com.example.layanalyzer.model.RtpDecodedItem
import com.example.layanalyzer.model.RtpProgress
import com.example.layanalyzer.model.RtpRawExportResult
import com.example.layanalyzer.model.RtpRawOrder
import com.example.layanalyzer.model.RtpScanResult
import com.example.layanalyzer.model.RtpStream
import com.example.layanalyzer.model.RtpVideoExportResult
import java.io.File
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Rule
import org.junit.Test
import org.junit.rules.TemporaryFolder

/**
 * RTP5-KT-04：音视频合成的 ViewModel 流程。
 *
 * 用注入的 fake 仓库、fake 编码器与 fake 封装器，把「WAV 渲染了没有」「编码器拿到的是
 * 不是那个 WAV」「封装器拿到的两个时间基准是不是这两条流自己的 `firstAbsEpochUs`」
 * 与「失败/取消之后盘上还剩什么」变成可观测的断言。
 *
 * **没有**断言的东西：真机上 `MediaCodec` 编出来的 AAC 与 `MediaMuxer` 写出来的 MP4。
 * 那需要设备，归属 `AudioVideoMuxerTest`（仪器测试，本机跑不了）。
 */
class RtpAudioVideoExportViewModelTest {
    @get:Rule
    val temporaryFolder = TemporaryFolder()

    @Test
    fun `a ready pair runs the encoder and the muxer and publishes the file`() {
        val harness = harness()
        val copied = File(temporaryFolder.root, "copied.mp4")

        harness.viewModel.exportAudioVideo(
            stream = harness.videoStream(),
            calls = listOf(harness.call()),
            destination = RtpExportDestination("v0.mp4") { source ->
                copied.writeBytes(source.readBytes())
            }
        )

        val state = harness.viewModel.avMuxState.value as RtpAvMuxUiState.Finished
        assertEquals("v0.mp4", state.file.displayName)
        assertEquals(VideoMuxFormat.MIME_MP4, state.file.mimeType)
        assertTrue(copied.isFile)
        assertEquals(900, state.videoFrames)
        assertEquals(40, state.audioSamples)
        assertEquals(0, state.droppedAudioSamples)
        assertEquals(500_000L, state.audioOffsetUs)

        // 音频那半：WAV 只有一条（就是那条音频流），交给编码器的是渲染出来的那个文件。
        assertEquals(listOf(listOf("a0")), harness.repository.decodeRequests.map { it.streamIds })
        assertEquals("a0", harness.repository.decodeRequests.single().streamIds.single())
        val (wav, m4a) = harness.exporter.requests.single()
        assertTrue(wav.isFile)
        assertEquals("a0.wav", wav.name)
        assertEquals("a0.m4a", m4a.name)
        assertTrue(m4a.isFile)

        // 视频那半与卡片的对齐规则：两个基准就是两条流自己的首包 epoch。
        val request = harness.muxer.requests.single()
        assertEquals("v0.h264", request.esFile.name)
        assertEquals("v0.vidx", request.vidxFile.name)
        assertEquals("H264", request.codec)
        assertEquals(1280, request.width)
        assertEquals(720, request.height)
        assertEquals(2_000_000L, request.videoStartEpochUs)
        assertEquals(1_700_000L, request.audioStartEpochUs)
        assertEquals(m4a.absolutePath, request.audioFile.absolutePath)
        assertEquals(File(state.file.filePath).name, request.outFile.name)
        assertTrue(File(state.file.filePath).startsWith(harness.cacheRoot))
    }

    @Test
    fun `the rendered wav is reused instead of rendered twice`() {
        val harness = harness()
        val calls = listOf(harness.call())

        harness.viewModel.exportAudioVideo(
            harness.videoStream(), calls, RtpExportDestination("one.mp4") { }
        )
        harness.viewModel.clearAvMuxState()
        harness.viewModel.exportAudioVideo(
            harness.videoStream(), calls, RtpExportDestination("two.mp4") { }
        )

        // 第二次合成用的是缓存里那个 WAV（与播放器同一份），没有第二次原生渲染。
        assertEquals(1, harness.repository.decodeRequests.size)
        assertEquals(2, harness.exporter.requests.size)
        assertEquals(
            harness.exporter.requests[0].first.absolutePath,
            harness.exporter.requests[1].first.absolutePath
        )
    }

    @Test
    fun `a failed encoder leaves neither an m4a nor an mp4`() {
        val harness = harness()
        harness.exporter.result = { AacExportResult.Unsupported("noEncoder") }

        harness.viewModel.exportAudioVideo(
            harness.videoStream(), listOf(harness.call()), RtpExportDestination("v0.mp4") { }
        )

        val state = harness.viewModel.avMuxState.value as RtpAvMuxUiState.Error
        assertEquals("noEncoder", state.message)
        assertTrue(harness.muxer.requests.isEmpty())
        assertFalse(harness.cacheFiles().any { it.name.endsWith(".mp4") })
        assertFalse(harness.cacheFiles().any { it.name.endsWith(".m4a") })
        // 渲染好的 WAV 留着：它是解码缓存里的东西，与播放器共用，不是这次请求的产物。
        assertTrue(harness.cacheFiles().any { it.name == "a0.wav" })
    }

    @Test
    fun `a mux failure leaves no half written mp4`() {
        val harness = harness()
        harness.muxer.result = { AvMuxResult.Failed("audioAllDropped") }

        harness.viewModel.exportAudioVideo(
            harness.videoStream(), listOf(harness.call()), RtpExportDestination("v0.mp4") { }
        )

        val state = harness.viewModel.avMuxState.value as RtpAvMuxUiState.Error
        assertEquals("audioAllDropped", state.message)
        assertFalse(harness.cacheFiles().any { it.name.endsWith(".mp4") })
        assertFalse(harness.cacheFiles().any { it.name.endsWith(".m4a") })
    }

    @Test
    fun `a cancelled video export leaves no half written mp4`() {
        val harness = harness()
        harness.repository.videoResult = { RtpVideoExportResult(cancelled = true, codec = "H264") }

        harness.viewModel.exportAudioVideo(
            harness.videoStream(), listOf(harness.call()), RtpExportDestination("v0.mp4") { }
        )

        assertTrue(harness.viewModel.avMuxState.value is RtpAvMuxUiState.Error)
        assertTrue(harness.muxer.requests.isEmpty())
        assertFalse(harness.cacheFiles().any { it.name.endsWith(".mp4") })
        assertFalse(harness.cacheFiles().any { it.name.endsWith(".m4a") })
    }

    @Test
    fun `an export without a scan is refused before anything is rendered`() {
        val harness = harness(scan = false)

        harness.viewModel.exportAudioVideo(
            stream = scanResult().streams.first { it.id == "v0" },
            calls = emptyList(),
            destination = RtpExportDestination("v0.mp4") { }
        )

        assertTrue(harness.viewModel.avMuxState.value is RtpAvMuxUiState.Error)
        assertTrue(harness.repository.decodeRequests.isEmpty())
        assertTrue(harness.exporter.requests.isEmpty())
        assertTrue(harness.muxer.requests.isEmpty())
    }

    // ------------------------------------------------------------ 可用性信号

    @Test
    fun `the availability signal distinguishes every reason`() {
        val harness = harness()
        val probe = harness.probe
        val video = harness.videoStream()

        harness.viewModel.refreshAvMuxAvailability(video)
        assertEquals(RtpAvMuxAvailability.NoCall, harness.viewModel.avMuxAvailability.value)

        harness.viewModel.refreshAvMuxAvailability(video, listOf(harness.call(audio = false)))
        assertEquals(
            RtpAvMuxAvailability.CallHasNoAudio("c1"),
            harness.viewModel.avMuxAvailability.value
        )

        probe.answer = false
        harness.viewModel.refreshAvMuxAvailability(video, listOf(harness.call()))
        assertEquals(RtpAvMuxAvailability.NoAacEncoder, harness.viewModel.avMuxAvailability.value)

        probe.answer = true
        harness.viewModel.refreshAvMuxAvailability(video, listOf(harness.call()))
        assertEquals(
            RtpAvMuxAvailability.Ready("c1", "a0"),
            harness.viewModel.avMuxAvailability.value
        )
        // 可用性只问设备一次，不碰文件：从来没有人渲染过 WAV。
        assertTrue(harness.repository.decodeRequests.isEmpty())
        assertTrue(harness.exporter.requests.isEmpty())
        assertTrue(harness.cacheFiles().isEmpty())
    }

    @Test
    fun `an unavailable export is refused with the reason and writes nothing`() {
        val harness = harness(hasAacEncoder = false)

        harness.viewModel.exportAudioVideo(
            harness.videoStream(),
            listOf(harness.call()),
            RtpExportDestination("v0.mp4") { }
        )

        val state = harness.viewModel.avMuxState.value as RtpAvMuxUiState.Error
        assertEquals("This device has no AAC encoder, so the audio cannot be combined.", state.message)
        assertEquals(RtpAvMuxAvailability.NoAacEncoder, harness.viewModel.avMuxAvailability.value)
        assertTrue(harness.repository.decodeRequests.isEmpty())
        assertTrue(harness.cacheFiles().isEmpty())
    }

    // ---------------------------------------------------------------- 夹具

    private class Harness(
        val viewModel: RtpViewModel,
        val repository: FakeRtpRepository,
        val exporter: FakeAacTrackExporter,
        val muxer: FakeAudioVideoMuxer,
        val probe: FakeAacEncoderProbe,
        val cacheRoot: File
    ) {
        fun streams(): List<RtpStream> =
            (viewModel.state.value as RtpScanUiState.Done).result.streams

        fun videoStream(): RtpStream = checkNotNull(videoStreamOrNull())

        fun videoStreamOrNull(): RtpStream? = streams().firstOrNull { it.id == "v0" }

        fun audioStream(): RtpStream = streams().first { it.id == "a0" }

        /** 这条视频流所属的、M3 会给出的那个呼叫。 */
        fun call(audio: Boolean = true, callId: String = "c1"): VoipCall = VoipCall(
            callId = callId, from = "", to = "", state = VoipCallState.IN_CALL,
            startRel = 0.0, setupMs = null, ringMs = null, durationMs = null,
            sipFrames = emptyList(), sdpFrames = emptyList(),
            streams = buildList {
                add(linked(videoStream(), RtpStreamDirection.REVERSE))
                if (audio) add(linked(audioStream(), RtpStreamDirection.FORWARD))
            },
            mos = null
        )

        fun cacheFiles(): List<File> = cacheRoot.walkTopDown().filter { it.isFile }.toList()

        private fun linked(stream: RtpStream, direction: RtpStreamDirection): LinkedRtpStream =
            LinkedRtpStream(
                stream = stream,
                direction = direction,
                linkReason = RtpLinkReason.SDP_ADDRESS_PORT,
                callId = "c1"
            )
    }

    private fun harness(
        scan: Boolean = true,
        hasAacEncoder: Boolean? = true
    ): Harness {
        val cacheRoot = File(temporaryFolder.root, "rtp-av-${System.nanoTime()}")
        val cache = RtpMediaCache(cacheRoot)
        val repository = FakeRtpRepository().apply { scanResult = scanResult() }
        val exporter = FakeAacTrackExporter()
        val muxer = FakeAudioVideoMuxer()
        val probe = FakeAacEncoderProbe(hasAacEncoder)
        val file = temporaryFolder.newFile("capture-av-${System.nanoTime()}.pcap")
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
            cacheRoot = cacheRoot,
            avMuxer = muxer,
            aacExporter = exporter,
            aacEncoderProbe = probe
        )
        if (scan) viewModel.scan()
        return Harness(viewModel, repository, exporter, muxer, probe, cacheRoot)
    }

    private class FakeAacEncoderProbe(var answer: Boolean?) : AacEncoderProbe {
        override fun hasEncoder(): Boolean? = answer
    }

    private class FakeAacTrackExporter : AacTrackExporter {
        val requests = mutableListOf<Pair<File, File>>()
        var cancelCount = 0
        var result: (File) -> AacExportResult = { out ->
            AacExportResult.Ok(
                m4aPath = out.absolutePath,
                sampleRate = 8_000,
                channels = 1,
                durationMs = 1_000L
            )
        }

        override suspend fun export(
            wavFile: File,
            outFile: File,
            onProgress: ((done: Int, total: Int) -> Unit)?
        ): AacExportResult {
            requests += wavFile to outFile
            onProgress?.invoke(1, 1)
            val outcome = result(outFile)
            if (outcome is AacExportResult.Ok) outFile.writeBytes(byteArrayOf(1, 2, 3))
            return outcome
        }

        override fun cancel() {
            cancelCount++
        }
    }

    private data class AvMuxRequest(
        val esFile: File,
        val vidxFile: File,
        val codec: String,
        val width: Int,
        val height: Int,
        val paramSets: VideoParamSets,
        val audioFile: File,
        val outFile: File,
        val videoStartEpochUs: Long,
        val audioStartEpochUs: Long
    )

    private class FakeAudioVideoMuxer : AudioVideoMuxer {
        val requests = mutableListOf<AvMuxRequest>()
        var cancelCount = 0
        var result: (File) -> AvMuxResult = { out ->
            AvMuxResult.Ok(
                mp4Path = out.absolutePath,
                videoFrames = 900,
                audioSamples = 40,
                droppedAudioSamples = 0,
                offsetUs = 500_000L,
                durationMs = 30_000L,
                nonMonotonicPtsCount = 0
            )
        }

        override suspend fun mux(
            esFile: File,
            vidxFile: File,
            codec: String,
            width: Int,
            height: Int,
            paramSets: VideoParamSets,
            audioFile: File,
            outFile: File,
            videoStartEpochUs: Long,
            audioStartEpochUs: Long
        ): AvMuxResult {
            requests += AvMuxRequest(
                esFile = esFile,
                vidxFile = vidxFile,
                codec = codec,
                width = width,
                height = height,
                paramSets = paramSets,
                audioFile = audioFile,
                outFile = outFile,
                videoStartEpochUs = videoStartEpochUs,
                audioStartEpochUs = audioStartEpochUs
            )
            val outcome = result(outFile)
            if (outcome is AvMuxResult.Ok) outFile.writeBytes(byteArrayOf(0, 0, 0, 1))
            return outcome
        }

        override fun cancel() {
            cancelCount++
        }
    }

    private class FakeRtpRepository : RtpRepository(PacketRepository()) {
        var scanResult: RtpScanResult = scanResult()
        val decodeRequests = mutableListOf<RtpDecodeRequest>()
        var videoResult: (File) -> RtpVideoExportResult = { outDir ->
            val es = File(outDir, "v0.h264")
            val vidx = File(outDir, "v0.vidx")
            es.writeBytes(byteArrayOf(0, 0, 0, 1, 0x67))
            vidx.writeBytes(byteArrayOf(0x56, 0x49, 0x44, 0x31))
            RtpVideoExportResult(
                schemaVersion = 1,
                esPath = es.absolutePath,
                indexPath = vidx.absolutePath,
                codec = "H264",
                width = 1280,
                height = 720,
                profile = "High",
                level = "3.1",
                frames = 900L,
                keyframes = 30L,
                corruptFrames = 0L,
                firstKeyframeIndex = 0L,
                durationMs = 30_000L,
                fpsEstimate = 30.0
            )
        }

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
            val items = request.streamIds.map { streamId ->
                val file = File(outDir, "$streamId.wav")
                file.writeBytes(byteArrayOf(1, 2, 3))
                RtpDecodedItem(
                    streamId = streamId,
                    codec = "g711A",
                    sampleRate = 8_000,
                    channels = 1,
                    wavPath = file.absolutePath,
                    peaksPath = "",
                    mapPath = "",
                    durationMs = 1_000L,
                    startRel = 0.0,
                    startAbsEpochMs = 0L,
                    gaps = emptyList(),
                    events = emptyList(),
                    stats = RtpDecodeStats(1L, 0L, 0L, 0L, 0L)
                )
            }
            return RtpDecodeResult("", false, items, emptyList())
        }

        override fun exportVideo(
            scanGeneration: Long,
            streamId: String,
            codec: String,
            startAtKeyframe: Boolean,
            dropCorrupt: Boolean,
            outDir: File,
            paramSets: VideoParamSets?,
            tsRate: Int?,
            donDiff: Int?,
            paramSetsPresentInStream: Boolean?,
            onProgress: ((RtpProgress) -> Boolean)?
        ): RtpVideoExportResult = videoResult(outDir)

        override fun exportRaw(
            scanGeneration: Long,
            streamId: String,
            order: RtpRawOrder,
            outFile: File
        ): RtpRawExportResult = RtpRawExportResult(0L, 0L, "not used")
    }

    private companion object {
        const val SESSION_HANDLE = 1L
    }
}

/**
 * 两条流、一个扫描结果：`v0` 是 2.000000 s 处的 H.264，`a0` 是 1.700000 s 处的
 * G.711A（音频先到 0.3 s）。
 */
private fun scanResult(): RtpScanResult {
    val video = """
        {
          "id":"v0", "src":"10.0.0.1", "srcPort":40000,
          "dst":"10.0.0.2", "dstPort":30000, "ssrc":1,
          "ssrcHex":"0x00000001", "pt":97, "codec":"H264",
          "codecSource":"sdp", "clockRate":90000, "decodable":"yes",
          "firstAbsEpochUs":2000000
        }
        """.trimIndent()
    val audio = """
        {
          "id":"a0", "src":"10.0.0.2", "srcPort":30000,
          "dst":"10.0.0.1", "dstPort":40000, "ssrc":2,
          "ssrcHex":"0x00000002", "pt":8, "codec":"g711A",
          "codecSource":"static", "clockRate":8000, "decodable":"yes",
          "firstAbsEpochUs":1700000
        }
        """.trimIndent()
    return RtpRepository(PacketRepository()).parseScanResult(
        """
        {
          "schemaVersion":1, "error":"", "cancelled":false,
          "scanGeneration":7, "framesScanned":10, "heuristicEnabled":false,
          "streamsTruncated":false, "streams":[$video,$audio]
        }
        """.trimIndent()
    )
}
