package com.example.layanalyzer.viewmodel

import android.view.Surface
import com.example.layanalyzer.ai.tools.AgentToolTestHarness
import com.example.layanalyzer.data.CaptureSessionCoordinator
import com.example.layanalyzer.data.PacketRepository
import com.example.layanalyzer.data.RtpMediaCache
import com.example.layanalyzer.data.RtpRepository
import com.example.layanalyzer.media.RtpPlayerState
import com.example.layanalyzer.media.RtpVideoPreviewController
import com.example.layanalyzer.media.VideoDecoderProbe
import com.example.layanalyzer.media.VideoPreviewPlayerFacade
import com.example.layanalyzer.media.VidxEntry
import com.example.layanalyzer.media.VidxFile
import com.example.layanalyzer.model.RtpScanResult
import com.example.layanalyzer.model.RtpStream
import com.example.layanalyzer.model.RtpVideoPreviewAvailability
import java.io.File
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Rule
import org.junit.Test
import org.junit.rules.TemporaryFolder

/**
 * RTP5-KT-03：预览可用性判定与打开/关闭的 ViewModel 单测。
 *
 * `.vidx` 用 RTP5-KT-01 的 [VidxFile.write] 真的写一个文件出来（那个 writer 就是为
 * 「让别的测试有索引可读」而存在的），所以这里测的是**真的读盘**，不是打桩过的解析。
 * 播放器仍然是假的（`MediaPlayer` 在本模块的 JVM 单测里碰不了），它只回答两件事：
 * 「数据源给了没有」「准备好了没有」。
 *
 * 没有断言的东西：进度条上的标红、`TextureView` 的 Surface 生命周期、真机上
 * `MediaPlayer` 能不能解这个 MP4 —— 那些要么没有设备（RTP5-QA-03），要么在
 * `RtpVideoPreviewControllerTest` 里明确写成「不可测」。
 */
class RtpVideoPreviewViewModelTest {

    @get:Rule
    val temporaryFolder = TemporaryFolder()

    @Test
    fun `refresh reports ready with both paths and asks for the codec decoder`() {
        val harness = harness("H265")
        val mp4 = harness.writeMp4()
        val vidx = harness.writeIndex(listOf(entry(0L, 12)))

        harness.viewModel.refreshVideoPreviewAvailability(
            stream = harness.stream(),
            mp4Path = mp4.absolutePath,
            indexPath = vidx.absolutePath
        )

        val availability = harness.viewModel.videoPreviewAvailability.value
        assertTrue(availability is RtpVideoPreviewAvailability.Ready)
        val ready = availability as RtpVideoPreviewAvailability.Ready
        assertEquals(mp4.absolutePath, ready.mp4Path)
        assertEquals(vidx.absolutePath, ready.indexPath)
        // 问的是轨道的 MIME（MediaCodecList 的话），不是文件打开的 MIME。
        assertEquals(listOf("video/hevc"), harness.probe.queries)
    }

    @Test
    fun `an h264 stream asks about avc`() {
        val harness = harness("H264")
        harness.viewModel.refreshVideoPreviewAvailability(
            stream = harness.stream(),
            mp4Path = harness.writeMp4().absolutePath,
            indexPath = harness.writeIndex(listOf(entry(0L, 12))).absolutePath
        )

        assertEquals(listOf("video/avc"), harness.probe.queries)
        assertTrue(
            harness.viewModel.videoPreviewAvailability.value
                is RtpVideoPreviewAvailability.Ready
        )
    }

    @Test
    fun `a missing mp4 is no export and the decoder is never asked`() {
        val harness = harness("H265")
        val vidx = harness.writeIndex(listOf(entry(0L, 12)))

        harness.viewModel.refreshVideoPreviewAvailability(
            stream = harness.stream(),
            mp4Path = File(harness.cacheRoot, "absent.mp4").absolutePath,
            indexPath = vidx.absolutePath
        )

        assertEquals(
            RtpVideoPreviewAvailability.NoExport,
            harness.viewModel.videoPreviewAvailability.value
        )
        // 文件都没有就不该去问解码器：那会把「没导出」和「设备不行」混起来。
        assertTrue(harness.probe.queries.isEmpty())
    }

    @Test
    fun `a missing index is no export too`() {
        val harness = harness("H264")

        harness.viewModel.refreshVideoPreviewAvailability(
            stream = harness.stream(),
            mp4Path = harness.writeMp4().absolutePath,
            indexPath = File(harness.cacheRoot, "absent.vidx").absolutePath
        )

        assertEquals(
            RtpVideoPreviewAvailability.NoExport,
            harness.viewModel.videoPreviewAvailability.value
        )
        assertTrue(harness.probe.queries.isEmpty())
    }

    @Test
    fun `no decoder is a different answer from no export`() {
        val harness = harness("H265", hasDecoder = false)

        harness.viewModel.refreshVideoPreviewAvailability(
            stream = harness.stream(),
            mp4Path = harness.writeMp4().absolutePath,
            indexPath = harness.writeIndex(listOf(entry(0L, 12))).absolutePath
        )

        // 「本机解不开」与「没有文件可播」是两件事，卡片点名要分开。
        assertEquals(
            RtpVideoPreviewAvailability.UnsupportedCodec("H265"),
            harness.viewModel.videoPreviewAvailability.value
        )
    }

    @Test
    fun `a failed decoder query is ready rather than unsupported`() {
        val harness = harness("H265", hasDecoder = null)

        harness.viewModel.refreshVideoPreviewAvailability(
            stream = harness.stream(),
            mp4Path = harness.writeMp4().absolutePath,
            indexPath = harness.writeIndex(listOf(entry(0L, 12))).absolutePath
        )

        // 查询失败不等于没有解码器：fail-open，功能不因为一次异常被藏起来。
        assertTrue(
            harness.viewModel.videoPreviewAvailability.value
                is RtpVideoPreviewAvailability.Ready
        )
    }

    @Test
    fun `a stream that is not a video codec has no preview`() {
        val harness = harness("g711A")

        harness.viewModel.refreshVideoPreviewAvailability(
            stream = harness.stream(),
            mp4Path = harness.writeMp4().absolutePath,
            indexPath = harness.writeIndex(listOf(entry(0L, 12))).absolutePath
        )

        assertEquals(
            RtpVideoPreviewAvailability.NoExport,
            harness.viewModel.videoPreviewAvailability.value
        )
        assertTrue(harness.probe.queries.isEmpty())
    }

    @Test
    fun `open loads the mp4 and publishes the access units`() {
        val harness = harness("H264")
        val mp4 = harness.writeMp4()
        val vidx = harness.writeIndex(
            listOf(
                entry(0L, 12, VidxFile.FLAG_KEY),
                entry(33_333L, 13, VidxFile.FLAG_CORRUPT),
                entry(66_666L, 15, VidxFile.FLAG_KEY)
            )
        )

        harness.viewModel.openVideoPreview(
            stream = harness.stream(),
            mp4Path = mp4.absolutePath,
            indexPath = vidx.absolutePath
        )

        val state = harness.viewModel.videoPreview.value
        assertTrue(state.isOpen)
        assertEquals(mp4.absolutePath, state.mp4Path)
        assertEquals(3, state.accessUnits.size)
        assertEquals(listOf(12, 13, 15), state.accessUnits.map { it.firstFrame })
        assertEquals(1, state.corruptFrameCount)
        assertEquals(null, state.indexError)
        // 播放器拿到了同一个文件，并且已经进入准备。
        assertEquals(listOf(mp4.absolutePath), harness.facade.dataSources)
        assertEquals(RtpPlayerState.Preparing, harness.viewModel.videoPreviewPlaybackState.value)
    }

    @Test
    fun `an unreadable index still plays the video and says what is missing`() {
        val harness = harness("H264")
        val mp4 = harness.writeMp4()
        val vidx = File(harness.cacheRoot, "s0.vidx").apply { writeText("not a vidx") }

        harness.viewModel.openVideoPreview(
            stream = harness.stream(),
            mp4Path = mp4.absolutePath,
            indexPath = vidx.absolutePath
        )

        val state = harness.viewModel.videoPreview.value
        // 少了包号不等于「打不开」：视频照放，缺什么写在 indexError 里。
        assertTrue(state.isOpen)
        assertTrue(state.accessUnits.isEmpty())
        assertEquals(0, state.corruptFrameCount)
        assertTrue(!state.indexError.isNullOrBlank())
        assertEquals(listOf(mp4.absolutePath), harness.facade.dataSources)
        assertEquals(RtpPlayerState.Preparing, harness.viewModel.videoPreviewPlaybackState.value)
    }

    @Test
    fun `open without the mp4 reports why and never loads the player`() {
        val harness = harness("H264")

        harness.viewModel.openVideoPreview(
            stream = harness.stream(),
            mp4Path = File(harness.cacheRoot, "absent.mp4").absolutePath,
            indexPath = harness.writeIndex(listOf(entry(0L, 12))).absolutePath
        )

        val state = harness.viewModel.videoPreview.value
        assertTrue(!state.isOpen)
        // 拒绝打开时说清楚是哪一种；界面按可用性渲染本地化文案，这里钉的是语义。
        assertEquals("There is no exported MP4 to preview.", state.errorMessage)
        assertTrue(harness.facade.dataSources.isEmpty())
    }

    @Test
    fun `open without a decoder reports why and never loads the player`() {
        val harness = harness("H265", hasDecoder = false)

        harness.viewModel.openVideoPreview(
            stream = harness.stream(),
            mp4Path = harness.writeMp4().absolutePath,
            indexPath = harness.writeIndex(listOf(entry(0L, 12))).absolutePath
        )

        val state = harness.viewModel.videoPreview.value
        assertTrue(!state.isOpen)
        assertEquals("This device has no decoder for this video codec.", state.errorMessage)
        assertEquals(
            RtpVideoPreviewAvailability.UnsupportedCodec("H265"),
            harness.viewModel.videoPreviewAvailability.value
        )
        assertTrue(harness.facade.dataSources.isEmpty())
    }

    @Test
    fun `close clears the page but keeps the availability`() {
        val harness = harness("H264")
        harness.viewModel.openVideoPreview(
            stream = harness.stream(),
            mp4Path = harness.writeMp4().absolutePath,
            indexPath = harness.writeIndex(listOf(entry(0L, 12))).absolutePath
        )
        assertTrue(harness.viewModel.videoPreview.value.isOpen)

        harness.viewModel.closeVideoPreview()

        val state = harness.viewModel.videoPreview.value
        assertTrue(!state.isOpen)
        assertEquals(0, state.accessUnits.size)
        // 文件还在盘上，UI-01 的菜单项不该因为关了一下预览就消失。
        assertTrue(
            harness.viewModel.videoPreviewAvailability.value
                is RtpVideoPreviewAvailability.Ready
        )
    }

    @Test
    fun `a session change resets the preview and its availability`() {
        val harness = harness("H264")
        harness.viewModel.openVideoPreview(
            stream = harness.stream(),
            mp4Path = harness.writeMp4().absolutePath,
            indexPath = harness.writeIndex(listOf(entry(0L, 12))).absolutePath
        )
        assertTrue(harness.viewModel.videoPreview.value.isOpen)

        // 预览的 MP4 在**会话自己的**缓存目录里：会话一变它就已经不存在了。
        harness.coordinator.invalidateSession()

        assertTrue(!harness.viewModel.videoPreview.value.isOpen)
        assertEquals(
            RtpVideoPreviewAvailability.NoExport,
            harness.viewModel.videoPreviewAvailability.value
        )
    }

    private class Harness(
        val viewModel: RtpViewModel,
        val probe: FakeVideoDecoderProbe,
        val facade: FakeVideoPreviewFacade,
        val coordinator: CaptureSessionCoordinator,
        val cacheRoot: File
    ) {
        /** 扫描结果里唯一的那条流（`scanResult` 只造了一条）。 */
        fun stream(): RtpStream =
            (viewModel.state.value as RtpScanUiState.Done).result.streams.single()

        /** 一个「导出的 MP4」：内容不重要，预览这一层只把路径交给播放器。 */
        fun writeMp4(): File = File(cacheRoot, "s0.mp4").apply {
            writeBytes(byteArrayOf(0, 0, 0, 0x18, 0x66, 0x74, 0x79, 0x70))
        }

        /** 用 RTP5-KT-01 的 writer 写一个真的 `.vidx`，好让 ViewModel 真的读一次盘。 */
        fun writeIndex(entries: List<VidxEntry>): File =
            File(cacheRoot, "s0.vidx").also { VidxFile.write(it, entries) }
    }

    private fun harness(codec: String, hasDecoder: Boolean? = true): Harness {
        val cacheRoot = File(temporaryFolder.root, "rtp-preview-$codec-${System.nanoTime()}")
        // 缓存根平时是 `RtpMediaCache.dirFor` 建的；这里不经过导出，自己建一下，
        // 好让「盘上真的有一个 MP4 与一个 .vidx」成立。
        check(cacheRoot.mkdirs()) { "Unable to create the test cache root." }
        val cache = RtpMediaCache(cacheRoot)
        val repository = FakeRtpRepository().apply { scanResult = scanResult("s0", codec) }
        val probe = FakeVideoDecoderProbe(hasDecoder)
        val facade = FakeVideoPreviewFacade()
        val file = temporaryFolder.newFile("capture-preview-${System.nanoTime()}.pcap")
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
            videoDecoderProbe = probe,
            videoPreviewController = RtpVideoPreviewController(
                facade = facade,
                scope = CoroutineScope(Dispatchers.Unconfined),
                tickMillis = 10_000L
            )
        )
        viewModel.scan()
        return Harness(viewModel, probe, facade, coordinator, cacheRoot)
    }

    private class FakeRtpRepository : RtpRepository(PacketRepository()) {
        var scanResult: RtpScanResult = scanResult("s0", "H264")

        override fun scanRtpStreams(
            limitToDisplayFilter: Boolean,
            onProgress: ((com.example.layanalyzer.model.RtpProgress) -> Boolean)?
        ): RtpScanResult = scanResult
    }

    private class FakeVideoDecoderProbe(private val answer: Boolean?) : VideoDecoderProbe {
        val queries = mutableListOf<String>()
        override fun hasDecoder(mime: String): Boolean? {
            queries += mime
            return answer
        }
    }

    /** 只回答「数据源给了什么」与「什么时候准备好」的假播放器。 */
    private class FakeVideoPreviewFacade : VideoPreviewPlayerFacade {
        val dataSources = mutableListOf<String>()

        override var durationMs: Long = 30_000L
        override val positionMs: Long get() = 0L
        override val isPlaying: Boolean get() = false

        override var onPrepared: (() -> Unit)? = null
        override var onCompletion: (() -> Unit)? = null
        override var onError: ((String) -> Unit)? = null
        override var onSeekComplete: (() -> Unit)? = null

        override fun setDataSource(path: String) {
            dataSources += path
        }

        override fun setSurface(surface: Surface?) = Unit
        override fun prepareAsync() = Unit
        override fun start() = Unit
        override fun pause() = Unit
        override fun seekTo(ms: Long) = Unit
        override fun release() = Unit
    }

    private companion object {
        const val SESSION_HANDLE = 1L
    }
}

/**
 * ViewModel 拒绝打开预览时给出的英文兜底文本，两条断言里直接写了字面量：界面按可用性渲染
 * 本地化的 `rtp_video_preview_missing` / `rtp_video_preview_no_decoder`，这里要钉的是
 * 「拒绝时说清楚了是哪一种」，而不是文案本身 —— 文案改了这两条测试也就跟着改。
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

private fun entry(ptsUs: Long, frame: Int, flags: Int = VidxFile.FLAG_KEY): VidxEntry =
    VidxEntry(offset = 0L, length = 8, ptsUs = ptsUs, firstFrame = frame, flags = flags)
