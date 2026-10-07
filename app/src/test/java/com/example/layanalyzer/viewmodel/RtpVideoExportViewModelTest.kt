// Copyright (c) 2026 cheig
// LayerAnalyzer - https://github.com/cheig/LayerAnalyzer
// Licensed under GNU GPL version 3; see LICENSE.

package com.example.layanalyzer.viewmodel

import com.example.layanalyzer.ai.tools.AgentToolTestHarness
import com.example.layanalyzer.data.CaptureSessionCoordinator
import com.example.layanalyzer.data.PacketRepository
import com.example.layanalyzer.data.RtpMediaCache
import com.example.layanalyzer.data.RtpRepository
import com.example.layanalyzer.data.VideoParamSets
import com.example.layanalyzer.media.RtpVideoMuxer
import com.example.layanalyzer.media.VideoDecoderProbe
import com.example.layanalyzer.media.VideoMuxResult
import com.example.layanalyzer.media.VideoMuxer
import com.example.layanalyzer.media.VideoMuxFormat
import com.example.layanalyzer.model.RtpProgress
import com.example.layanalyzer.model.RtpRawOrder
import com.example.layanalyzer.model.RtpRawExportResult
import com.example.layanalyzer.model.RtpScanResult
import com.example.layanalyzer.model.RtpStream
import com.example.layanalyzer.model.RtpVideoCodecData
import com.example.layanalyzer.model.RtpVideoDecoderAvailability
import com.example.layanalyzer.model.RtpVideoExportFormat
import com.example.layanalyzer.model.RtpVideoExportResult
import java.io.File
import java.util.Base64
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertTrue
import org.junit.Rule
import org.junit.Test
import org.junit.rules.TemporaryFolder

/**
 * RTP5-KT-02：视频导出（MP4 / 裸流）、外部打开准备与 HEVC 提示的 ViewModel 单测。
 *
 * 用注入的 fake 仓库、fake 封装器与 fake 探针，把「原生端点收到了什么请求」「ES 与
 * 索引有没有交给封装器」「没有解码器时提示了没有、导出还做不做」变成可观测的断言。
 *
 * **没有**断言的东西：真机上的端到端导出与外部打开（`MediaMuxer` / `MediaCodecList`
 * 在本模块的 JVM 单测里是 not mocked 的桩）—— 那需要设备与视频夹具，归属
 * RTP5-QA-02/03；卡片自己的自检「手工导出两种格式并外部打开」在本机做不了。
 */
class RtpVideoExportViewModelTest {
    @get:Rule
    val temporaryFolder = TemporaryFolder()

    @Test
    fun `the share results carry the M2 file name stem and the format mime`() {
        val raw = harness("H265")
        raw.viewModel.shareVideo(
            streams = raw.streams(),
            format = RtpVideoExportFormat.RAW
        )
        val rawState = raw.viewModel.videoExportState.value as RtpVideoExportUiState.Finished
        assertEquals("$EXPORT_STEM.h265", rawState.shareResults.single().displayName)
        assertEquals("video/hevc", rawState.shareResults.single().mimeType)

        val mp4 = harness("H264")
        mp4.viewModel.shareVideo(
            streams = mp4.streams(),
            format = RtpVideoExportFormat.MP4
        )
        val mp4State = mp4.viewModel.videoExportState.value as RtpVideoExportUiState.Finished
        assertEquals("$EXPORT_STEM.mp4", mp4State.shareResults.single().displayName)
        assertEquals("video/mp4", mp4State.shareResults.single().mimeType)
    }

    @Test
    fun `a raw export publishes the elementary stream the native endpoint wrote`() {
        val harness = harness("H264")
        val copied = File(temporaryFolder.root, "copied.h264")

        harness.viewModel.exportVideo(
            streams = harness.streams(),
            format = RtpVideoExportFormat.RAW,
            destinations = listOf(RtpExportDestination("s0.h264") { source ->
                copied.writeBytes(source.readBytes())
            })
        )

        val state = harness.viewModel.videoExportState.value as RtpVideoExportUiState.Finished
        assertEquals(RtpVideoExportFormat.RAW, state.summary.format)
        assertTrue(state.summary.failures.isEmpty())
        val file = state.summary.files.single()
        assertEquals("video/h264", file.mimeType)
        // 写到调用方给的 SAF 目的地时，显示名就用地名给的（与音频导出的口径一致）；
        // 分享路径上的显示名才是 M2 那条词干，见下面的 share 单测。
        assertEquals("s0.h264", file.displayName)
        assertTrue(copied.isFile)
        // 缓存里落的就是原生写出的那个文件（RTP5-NAT-05 的 `<streamId>.h264`）。
        assertEquals("s0.h264", File(file.filePath).name)
        assertTrue(File(file.filePath).startsWith(harness.cacheRoot))
        // 裸流不经过封装器。
        assertTrue(harness.muxer.requests.isEmpty())

        val request = harness.repository.videoRequests.single()
        assertEquals(listOf("s0", "H264"), listOf(request.streamId, request.codec))
        assertEquals(7L, request.scanGeneration)
        assertTrue(request.startAtKeyframe)
        assertTrue(!request.dropCorrupt)
        // 今天没有 SDP 参数集的来源，缺省就是 null（请求里不会出现 paramSets 键）。
        assertEquals(null, request.paramSets)

        val result = state.summary.results.getValue("s0")
        assertEquals(900L, result.frames)
        assertEquals(1280, result.width)
        assertEquals(720, result.height)
    }

    @Test
    fun `an mp4 export hands the es and its index to the muxer`() {
        val harness = harness("H264")

        harness.viewModel.exportVideo(
            streams = harness.streams(),
            format = RtpVideoExportFormat.MP4,
            destinations = listOf(RtpExportDestination("s0.mp4") { })
        )

        val state = harness.viewModel.videoExportState.value as RtpVideoExportUiState.Finished
        assertTrue(state.summary.failures.isEmpty())
        val file = state.summary.files.single()
        assertEquals("video/mp4", file.mimeType)
        assertEquals("s0.mp4", file.displayName)
        assertTrue(file.filePath.endsWith(".mp4"))
        assertTrue(File(file.filePath).startsWith(harness.cacheRoot))

        val mux = harness.muxer.requests.single()
        assertEquals("s0.h264", mux.esFile.name)
        assertEquals("s0.vidx", mux.vidxFile.name)
        assertEquals("H264", mux.codec)
        // 宽高取自原生结果（流里的 SPS 读出来的），不是调用方猜的。
        assertEquals(1280, mux.width)
        assertEquals(720, mux.height)
        // 调用方没有 SDP 参数集时，用原生结果里的 `csd`（写出的 ES 开头带的那组）——
        // 带内有 SPS/PPS 的流因此今天就能出一个 MP4。
        assertArrayEquals(REPORTED_SPS, mux.paramSets.sps.single())
        assertArrayEquals(REPORTED_PPS, mux.paramSets.pps.single())
        // 封装器的产物就是最终文件。
        assertEquals(File(file.filePath).name, mux.outFile.name)
    }

    @Test
    fun `the caller's sdp parameter sets win over the native report`() {
        val harness = harness("H264")

        harness.viewModel.exportVideo(
            streams = harness.streams(),
            format = RtpVideoExportFormat.MP4,
            destinations = listOf(RtpExportDestination("s0.mp4") { }),
            paramSets = callerParamSets(CALLER_SPS, CALLER_PPS)
        )

        val state = harness.viewModel.videoExportState.value as RtpVideoExportUiState.Finished
        assertTrue(state.summary.failures.isEmpty())
        val mux = harness.muxer.requests.single()
        // SDP 是权威值，也是 KT-01 卡片点名的来源：两边都有时听调用方的。
        assertArrayEquals(CALLER_SPS, mux.paramSets.sps.single())
        assertArrayEquals(CALLER_PPS, mux.paramSets.pps.single())
        // 请求里的 `paramSets`（注入用）与交给封装器的那组是两件事：调用方给了就照发。
        assertNotNull(harness.repository.videoRequests.single().paramSets)
    }

    @Test
    fun `a stream with no parameter sets anywhere still fails closed`() {
        val harness = harness("H264")
        // 原生报告「ES 里也没有参数集」，调用方也没有 SDP 的那份。
        harness.repository.reportedCsd = RtpVideoCodecData.EMPTY

        harness.viewModel.exportVideo(
            streams = harness.streams(),
            format = RtpVideoExportFormat.MP4,
            destinations = listOf(RtpExportDestination("s0.mp4") { })
        )

        val state = harness.viewModel.videoExportState.value as RtpVideoExportUiState.Finished
        assertEquals(listOf("s0"), state.summary.failures.map { it.streamId })
        assertEquals(RtpVideoMuxer.MISSING_PARAMETER_SETS, state.summary.failures.single().message)
        assertTrue(state.summary.files.isEmpty())
        // 两个来源都空 → 交给封装器的是空组 → 不生成坏 MP4。
        assertTrue(harness.muxer.requests.single().paramSets.sps.isEmpty())
        assertTrue(harness.cacheFiles().none { it.name.endsWith(".mp4") })
    }

    @Test
    fun `a mux failure is a failure and never silently becomes the raw stream`() {
        val harness = harness("H264")
        harness.muxer.result = { VideoMuxResult.Failed("missingParameterSets") }

        harness.viewModel.exportVideo(
            streams = harness.streams(),
            format = RtpVideoExportFormat.MP4,
            destinations = listOf(RtpExportDestination("s0.mp4") { })
        )

        val state = harness.viewModel.videoExportState.value as RtpVideoExportUiState.Finished
        assertEquals(listOf("s0"), state.summary.failures.map { it.streamId })
        assertEquals("missingParameterSets", state.summary.failures.single().message)
        assertTrue(state.summary.files.isEmpty())
        // README §4.5.4：真正的错误不许被降级成「换个文件给你」。
        assertTrue(harness.cacheFiles().none { it.name.endsWith(".mp4") })
        assertTrue(harness.cacheFiles().none { it.name.endsWith(".h264") })
    }

    @Test
    fun `a native failure never reaches the muxer`() {
        val harness = harness("H265")
        harness.repository.videoResult = {
            RtpVideoExportResult(error = "缺少参数集（SDP 与带内均未找到）", codec = "H265")
        }

        harness.viewModel.exportVideo(
            streams = harness.streams(),
            format = RtpVideoExportFormat.MP4,
            destinations = listOf(RtpExportDestination("s0.mp4") { })
        )

        val state = harness.viewModel.videoExportState.value as RtpVideoExportUiState.Finished
        assertEquals(
            "缺少参数集（SDP 与带内均未找到）",
            state.summary.failures.single().message
        )
        assertTrue(harness.muxer.requests.isEmpty())
        assertTrue(harness.cacheFiles().isEmpty())
    }

    @Test
    fun `a cancelled native export is a failure and leaves nothing behind`() {
        val harness = harness("H264")
        harness.repository.videoResult = {
            RtpVideoExportResult(cancelled = true, codec = "H264")
        }

        harness.viewModel.shareVideo(
            streams = harness.streams(),
            format = RtpVideoExportFormat.RAW
        )

        val state = harness.viewModel.videoExportState.value as RtpVideoExportUiState.Finished
        assertEquals(listOf("s0"), state.summary.failures.map { it.streamId })
        assertTrue(state.shareResults.isEmpty())
        assertTrue(harness.cacheFiles().isEmpty())
    }

    @Test
    fun `the start at keyframe and drop corrupt flags reach the native request`() {
        val harness = harness("H265")

        harness.viewModel.exportVideo(
            streams = harness.streams(),
            format = RtpVideoExportFormat.RAW,
            destinations = listOf(RtpExportDestination("s0.h265") { }),
            startAtKeyframe = false,
            dropCorrupt = true
        )

        val request = harness.repository.videoRequests.single()
        assertEquals("H265", request.codec)
        assertTrue(!request.startAtKeyframe)
        assertTrue(request.dropCorrupt)
    }

    @Test
    fun `no hevc decoder publishes a notice and the export still happens`() {
        val harness = harness("H265", hasHevcDecoder = false)

        harness.viewModel.exportVideo(
            streams = harness.streams(),
            format = RtpVideoExportFormat.RAW,
            destinations = listOf(RtpExportDestination("s0.h265") { })
        )

        val availability = harness.viewModel.hevcDecoderAvailability.value
        assertEquals(RtpVideoDecoderAvailability.MISSING, availability)
        // 卡片：提示，但**仍然允许导出**。
        assertTrue(availability.noticeRequired)
        assertTrue(availability.exportAllowed)
        val state = harness.viewModel.videoExportState.value as RtpVideoExportUiState.Finished
        assertTrue(state.summary.failures.isEmpty())
        assertEquals(1, state.summary.files.size)
        assertEquals(listOf(VideoMuxFormat.MIME_H265), harness.probe.queries)
    }

    @Test
    fun `a failed decoder query is unknown and does not become a notice`() {
        val harness = harness("H265", hasHevcDecoder = null)

        harness.viewModel.exportVideo(
            streams = harness.streams(),
            format = RtpVideoExportFormat.RAW,
            destinations = listOf(RtpExportDestination("s0.h265") { })
        )

        val availability = harness.viewModel.hevcDecoderAvailability.value
        assertEquals(RtpVideoDecoderAvailability.UNKNOWN, availability)
        assertTrue(!availability.noticeRequired)
        assertTrue(availability.exportAllowed)
    }

    @Test
    fun `an h264 stream never triggers the hevc probe`() {
        val harness = harness("H264", hasHevcDecoder = false)

        harness.viewModel.exportVideo(
            streams = harness.streams(),
            format = RtpVideoExportFormat.RAW,
            destinations = listOf(RtpExportDestination("s0.h264") { })
        )

        assertTrue(harness.probe.queries.isEmpty())
        assertEquals(
            RtpVideoDecoderAvailability.UNKNOWN,
            harness.viewModel.hevcDecoderAvailability.value
        )
    }

    @Test
    fun `open mime types prefer the codec mime and fall back to octet stream for a raw stream`() {
        val harness = harness("H264")
        assertEquals(
            listOf("video/h264", "application/octet-stream"),
            harness.viewModel.videoOpenMimeTypes("H264", RtpVideoExportFormat.RAW)
        )
        assertEquals(
            listOf("video/hevc", "application/octet-stream"),
            harness.viewModel.videoOpenMimeTypes("H265", RtpVideoExportFormat.RAW)
        )
    }

    @Test
    fun `the mp4 has one candidate and no generic fallback`() {
        val harness = harness("H264")
        assertEquals(
            listOf("video/mp4"),
            harness.viewModel.videoOpenMimeTypes("H264", RtpVideoExportFormat.MP4)
        )
    }

    @Test
    fun `open candidates keep the order and all point at the same file`() {
        val harness = harness("H264")
        val file = File(temporaryFolder.root, "s0.h264")

        val candidates = harness.viewModel.videoOpenCandidates(
            file,
            harness.viewModel.videoOpenMimeTypes("H264", RtpVideoExportFormat.RAW)
        )

        assertEquals(2, candidates.size)
        // 顺序就是回退顺序：`openFirstAvailable` 依次试，第一个能开的胜出。
        assertEquals("video/h264", candidates[0].mimeType)
        assertEquals("application/octet-stream", candidates[1].mimeType)
        assertTrue(candidates.all { it.file == file })
    }

    @Test
    fun `preview preparation ends before playback and stays idle after returning`() {
        val harness = harness("H264")
        harness.muxer.onMux = { onProgress ->
            onProgress?.invoke(100, 100)
            val preparing = harness.viewModel.videoOpenState.value as RtpVideoOpenUiState.Preparing
            assertEquals(RtpProgress(100, 100), preparing.progress)
        }

        harness.viewModel.prepareVideoPreview(harness.streams().single())

        assertTrue(harness.viewModel.videoPreview.value.isOpen)
        assertEquals(RtpVideoOpenUiState.Idle, harness.viewModel.videoOpenState.value)
        assertEquals(RtpVideoExportUiState.Idle, harness.viewModel.videoExportState.value)
        harness.viewModel.closeVideoPreview()
        assertFalse(harness.viewModel.videoPreview.value.isOpen)
        assertEquals(RtpVideoOpenUiState.Idle, harness.viewModel.videoOpenState.value)
    }

    @Test
    fun `preview preparation failure reports an error instead of remaining at full progress`() {
        val harness = harness("H264")
        harness.muxer.onMux = { it?.invoke(100, 100) }
        harness.muxer.result = { VideoMuxResult.Failed("muxFailed") }

        harness.viewModel.prepareVideoPreview(harness.streams().single())

        assertTrue(harness.viewModel.videoOpenState.value is RtpVideoOpenUiState.Error)
        assertFalse(harness.viewModel.videoPreview.value.isOpen)
    }

    @Test
    fun `prepareExternalVideoOpen publishes the raw file with both mime types`() {
        val harness = harness("H265")

        harness.viewModel.prepareExternalVideoOpen(
            stream = harness.streams().single(),
            format = RtpVideoExportFormat.RAW
        )

        val state = harness.viewModel.videoOpenState.value as RtpVideoOpenUiState.Ready
        assertEquals("s0", state.streamId)
        assertEquals(RtpVideoExportFormat.RAW, state.format)
        assertEquals(listOf("video/hevc", "application/octet-stream"), state.mimeTypes)
        val file = File(state.filePath)
        assertTrue(file.isFile)
        assertEquals("h265", file.extension)
        assertTrue(file.startsWith(harness.cacheRoot))
        assertTrue(harness.muxer.requests.isEmpty())
    }

    @Test
    fun `prepareExternalVideoOpen reports a failure instead of opening the wrong file`() {
        val harness = harness("H264")
        harness.repository.videoResult = {
            RtpVideoExportResult(error = "noKeyframe", codec = "H264")
        }

        harness.viewModel.prepareExternalVideoOpen(
            stream = harness.streams().single(),
            format = RtpVideoExportFormat.RAW
        )

        val state = harness.viewModel.videoOpenState.value as RtpVideoOpenUiState.Error
        assertEquals("noKeyframe", state.message)
    }

    @Test
    fun `prepareExternalVideoOpen refuses a stream that is not a video codec`() {
        val harness = harness("g711A")

        harness.viewModel.prepareExternalVideoOpen(harness.streams().single())

        assertTrue(harness.viewModel.videoOpenState.value is RtpVideoOpenUiState.Error)
        assertTrue(harness.repository.videoRequests.isEmpty())
    }

    @Test
    fun `a video export publishes native progress and then the mux phase`() {
        val harness = harness("H264")
        val seen = mutableListOf<RtpVideoExportUiState>()
        harness.repository.onVideoExport = { onProgress ->
            onProgress?.invoke(RtpProgress(46, 100))
            seen += harness.viewModel.videoExportState.value
        }
        harness.muxer.onMux = { onProgress ->
            seen += harness.viewModel.videoExportState.value
            onProgress?.invoke(50, 100)
            seen += harness.viewModel.videoExportState.value
        }

        harness.viewModel.exportVideo(
            streams = harness.streams(),
            format = RtpVideoExportFormat.MP4,
            destinations = listOf(RtpExportDestination("s0.mp4") { })
        )

        val extracting = seen[0] as RtpVideoExportUiState.Running
        assertEquals(RtpVideoExportPhase.EXTRACTING, extracting.phase)
        assertEquals(RtpProgress(46, 100), extracting.progress)
        val muxing = seen[1] as RtpVideoExportUiState.Running
        assertEquals(RtpVideoExportPhase.MUXING, muxing.phase)
        val muxProgress = seen[2] as RtpVideoExportUiState.Running
        assertEquals(RtpVideoExportPhase.MUXING, muxProgress.phase)
        assertEquals(RtpProgress(50, 100), muxProgress.progress)
        assertTrue(harness.viewModel.videoExportState.value is RtpVideoExportUiState.Finished)
    }

    @Test
    fun `cancelling a video export makes the next progress callback stop the walk`() {
        val harness = harness("H264")
        var keepGoing = true
        harness.repository.onVideoExport = { onProgress ->
            keepGoing = onProgress?.invoke(RtpProgress(10, 100)) ?: false
            harness.viewModel.cancelVideoExport()
            keepGoing = onProgress?.invoke(RtpProgress(20, 100)) ?: false
        }

        harness.viewModel.exportVideo(
            streams = harness.streams(),
            format = RtpVideoExportFormat.RAW,
            destinations = listOf(RtpExportDestination("s0.h264") { })
        )

        assertFalse(keepGoing)
        assertEquals(1, harness.muxer.cancelCount)
    }

    @Test
    fun `a video export needs a scan like the other export kinds`() {
        val harness = harness("H264", scan = false)

        harness.viewModel.exportVideo(
            streams = emptyList(),
            format = RtpVideoExportFormat.MP4,
            destinations = emptyList()
        )

        assertTrue(harness.viewModel.videoExportState.value is RtpVideoExportUiState.Error)
        assertTrue(harness.repository.videoRequests.isEmpty())
    }

    private class Harness(
        val viewModel: RtpViewModel,
        val repository: FakeRtpRepository,
        val muxer: FakeVideoMuxer,
        val probe: FakeVideoDecoderProbe,
        val cacheRoot: File
    ) {
        fun streams(): List<RtpStream> =
            (viewModel.state.value as RtpScanUiState.Done).result.streams

        fun cacheFiles(): List<File> = cacheRoot.walkTopDown().filter { it.isFile }.toList()
    }

    private fun harness(
        codec: String,
        scan: Boolean = true,
        hasHevcDecoder: Boolean? = true
    ): Harness {
        val cacheRoot = File(temporaryFolder.root, "rtp-video-$codec-${System.nanoTime()}")
        val cache = RtpMediaCache(cacheRoot)
        val repository = FakeRtpRepository().apply { scanResult = scanResult("s0", codec) }
        val muxer = FakeVideoMuxer()
        val probe = FakeVideoDecoderProbe(hasHevcDecoder)
        val file = temporaryFolder.newFile("capture-video-${System.nanoTime()}.pcap")
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
            videoMuxer = muxer,
            videoDecoderProbe = probe
        )
        if (scan) viewModel.scan()
        return Harness(viewModel, repository, muxer, probe, cacheRoot)
    }

    /** 一次 `exportVideo` 请求里被记录下来的那部分（断言请求契约用）。 */
    private data class VideoRequest(
        val scanGeneration: Long,
        val streamId: String,
        val codec: String,
        val startAtKeyframe: Boolean,
        val dropCorrupt: Boolean,
        val paramSets: VideoParamSets?,
        val outDir: File
    )

    private class FakeVideoMuxer : VideoMuxer {
        val requests = mutableListOf<MuxRequest>()
        var cancelCount = 0
        var result: (File) -> VideoMuxResult = { out ->
            VideoMuxResult.Ok(mp4Path = out.absolutePath, frames = 900, durationMs = 30_000L)
        }
        var onMux: (((done: Int, total: Int) -> Unit)?) -> Unit = {}

        override suspend fun mux(
            esFile: File,
            vidxFile: File,
            codec: String,
            width: Int,
            height: Int,
            paramSets: VideoParamSets,
            outFile: File,
            onProgress: ((done: Int, total: Int) -> Unit)?
        ): VideoMuxResult {
            requests += MuxRequest(esFile, vidxFile, codec, width, height, paramSets, outFile)
            onMux(onProgress)
            // 真机上的 KT-01 封装器对「描述不了轨道」的参数集 fail-closed（回
            // missingParameterSets）。fake 用 KT-01 自己的纯函数复现这条规则，好让
            // 「SDP 与带内都没有参数集」的用例仍然是一条真实的失败路径，而不是在测
            // 一个永远成功的假封装器。
            if (VideoMuxFormat.codecSpecificData(codec, paramSets) == null) {
                return VideoMuxResult.Failed(RtpVideoMuxer.MISSING_PARAMETER_SETS)
            }
            val outcome = result(outFile)
            if (outcome is VideoMuxResult.Ok) outFile.writeBytes(byteArrayOf(0, 0, 0, 1))
            return outcome
        }

        override fun cancel() {
            cancelCount++
        }
    }

    private data class MuxRequest(
        val esFile: File,
        val vidxFile: File,
        val codec: String,
        val width: Int,
        val height: Int,
        val paramSets: VideoParamSets,
        val outFile: File
    )

    private class FakeVideoDecoderProbe(private val answer: Boolean?) : VideoDecoderProbe {
        val queries = mutableListOf<String>()
        override fun hasDecoder(mime: String): Boolean? {
            queries += mime
            return answer
        }
    }

    private class FakeRtpRepository : RtpRepository(PacketRepository()) {
        var scanResult: RtpScanResult = scanResult("s0", "H264")

        /**
         * 原生结果里 `csd` —— 写出的 ES 开头带的那组参数集。默认给一组，模拟**带内**
         * 有 SPS/PPS 的流（卡片第二个 H.264 夹具就是这一类）；置成
         * [RtpVideoCodecData.EMPTY] 就是「哪里都没有参数集」。
         */
        var reportedCsd: RtpVideoCodecData = RtpVideoCodecData(
            sps = base64(REPORTED_SPS),
            pps = base64(REPORTED_PPS)
        )

        var videoResult: (VideoRequest) -> RtpVideoExportResult = { request ->
            val extension = if (request.codec == "H265") "h265" else "h264"
            val es = File(request.outDir, "s0.$extension")
            val vidx = File(request.outDir, "s0.vidx")
            es.writeBytes(byteArrayOf(0, 0, 0, 1, 0x67))
            vidx.writeBytes(byteArrayOf(0x56, 0x49, 0x44, 0x31))
            RtpVideoExportResult(
                schemaVersion = 1,
                esPath = es.absolutePath,
                indexPath = vidx.absolutePath,
                codec = request.codec,
                width = 1280,
                height = 720,
                profile = "High",
                level = "3.1",
                csd = reportedCsd,
                frames = 900L,
                keyframes = 30L,
                corruptFrames = 2L,
                firstKeyframeIndex = 0L,
                durationMs = 30_000L,
                fpsEstimate = 30.0
            )
        }

        val videoRequests = mutableListOf<VideoRequest>()
        var onVideoExport: (((RtpProgress) -> Boolean)?) -> Unit = {}

        override fun scanRtpStreams(
            limitToDisplayFilter: Boolean,
            onProgress: ((RtpProgress) -> Boolean)?
        ): RtpScanResult = scanResult

        override fun exportRaw(
            scanGeneration: Long,
            streamId: String,
            order: RtpRawOrder,
            outFile: File
        ): RtpRawExportResult = RtpRawExportResult(0L, 0L, "not used")

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
        ): RtpVideoExportResult {
            val request = VideoRequest(
                scanGeneration = scanGeneration,
                streamId = streamId,
                codec = codec,
                startAtKeyframe = startAtKeyframe,
                dropCorrupt = dropCorrupt,
                paramSets = paramSets,
                outDir = outDir
            )
            videoRequests += request
            onVideoExport(onProgress)
            return videoResult(request)
        }
    }

    /** 调用方（SDP）给的那组参数集，与原生报告的那组不同，好分辨是谁赢了。 */
    private fun callerParamSets(sps: ByteArray, pps: ByteArray) = VideoParamSets(
        sps = listOf(sps),
        pps = listOf(pps),
        vps = emptyList(),
        packetizationMode = 1,
        profileLevelId = "64001F",
        donDiff = null
    )

    private companion object {
        const val SESSION_HANDLE = 1L

        /** `rtp_<src>_<srcPort>-<dst>_<dstPort>_<ssrcHex>`，与 M2 的文件名同一条词干。 */
        const val EXPORT_STEM = "rtp_10.0.0.1_40000-10.0.0.2_30000_0x00000001"

        /**
         * 原生结果 `csd` 报告的参数集。字节是假造的：这里只做 Base64 → 字节的往返与
         * 「谁赢了」的判定，不解析 NAL（真实向量在 `media/VideoMuxFormatTest`）。
         */
        val REPORTED_SPS = byteArrayOf(0x67, 0x42, 0x00, 0x1E, 0x7F)
        val REPORTED_PPS = byteArrayOf(0x68, 0xCE.toByte(), 0x3C, 0x80.toByte())
        val CALLER_SPS = byteArrayOf(0x11, 0x22, 0x33, 0x44)
        val CALLER_PPS = byteArrayOf(0x55, 0x66)
    }
}

private fun base64(bytes: ByteArray): String = Base64.getEncoder().encodeToString(bytes)

/**
 * 一条视频流的扫描结果夹具（字段口径与同目录其它 RTP ViewModel 测试一致：
 * 一条流、可解码）。
 */
private fun scanResult(id: String, codec: String): RtpScanResult {
    val stream = """
        {
          "id":"$id", "src":"10.0.0.1", "srcPort":40000,
          "dst":"10.0.0.2", "dstPort":30000, "ssrc":1,
          "ssrcHex":"0x00000001", "pt":97, "codec":"$codec",
          "codecSource":"sdp", "clockRate":90000, "decodable":"yes"
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
