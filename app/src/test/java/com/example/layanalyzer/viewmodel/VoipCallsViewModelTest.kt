// Copyright (c) 2026 cheig
// LayerAnalyzer - https://github.com/cheig/LayerAnalyzer
// Licensed under GNU GPL version 3; see LICENSE.

package com.example.layanalyzer.viewmodel

import com.example.layanalyzer.ai.tools.AgentToolTestHarness
import com.example.layanalyzer.data.CaptureSessionCoordinator
import com.example.layanalyzer.data.PacketRepository
import com.example.layanalyzer.data.RtpMediaCache
import com.example.layanalyzer.data.RtpRepository
import com.example.layanalyzer.data.RtpStreamDirection
import com.example.layanalyzer.data.VoipCallState
import com.example.layanalyzer.model.CommunicationAnalysis
import com.example.layanalyzer.model.RtpCodecSource
import com.example.layanalyzer.model.RtpDecodability
import com.example.layanalyzer.model.RtpDecodeRequest
import com.example.layanalyzer.model.RtpDecodeResult
import com.example.layanalyzer.model.RtpMixRequest
import com.example.layanalyzer.model.RtpProgress
import com.example.layanalyzer.model.RtpScanResult
import com.example.layanalyzer.model.RtpStream
import com.example.layanalyzer.model.RtpTimingMode
import com.example.layanalyzer.model.RtpUnsupportedStream
import com.example.layanalyzer.model.SdpMediaSummary
import com.example.layanalyzer.model.SipMessage
import java.io.File
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.runBlocking
import org.json.JSONObject
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Rule
import org.junit.Test
import org.junit.rules.TemporaryFolder

/**
 * [VoipCallsViewModel] 的纯 JVM 单测（RTP3-KT-02）。
 *
 * 仓库里没有 Main dispatcher，也没有 kotlinx-coroutines-test，所以统一用
 * `runBlocking` + `Dispatchers.Unconfined`（`ioDispatcher` 与 `externalScope` 都注入
 * Unconfined，加载因此是同步完成的、可断言的）。
 *
 * SIP 夹具只给 [SipMessage]，dialog 由**真实的** [com.example.layanalyzer.data.SipTransactionCorrelator]
 * 在 ViewModel 里现算——不手工构造 `SipDialogTimeline`，否则就绕过了要验证的那条路径。
 */
class VoipCallsViewModelTest {

    @get:Rule
    val temporaryFolder = TemporaryFolder()

    // ------------------------------------------------------------ 场景 1：正常路径

    @Test
    fun `a sip dialog and its rtp streams publish one linked call`() {
        val repository = FakeVoipRtpRepository().apply {
            scanResult = scanResult(stream("s0"), stream("s1", fromCallee = true))
        }
        val viewModel = viewModel(repository, coordinatorWithSession(), cache())

        viewModel.load()

        val ready = ready(viewModel)
        assertEquals(1, ready.calls.size)
        val call = ready.calls.single()
        assertEquals(CALL_ID, call.callId)
        assertEquals(VoipCallState.IN_CALL, call.state)
        assertEquals(listOf("s0", "s1"), call.streams.map { it.stream.id })
        assertEquals(
            listOf(RtpStreamDirection.FORWARD, RtpStreamDirection.REVERSE),
            call.streams.map { it.direction }
        )
        assertTrue(ready.unlinked.isEmpty())
        assertFalse(ready.sipTruncated)
        assertTrue(ready.warnings.isEmpty())
        // RTP3-NAT-04 的 readRtpSetupInfo 还不存在，默认没有 From/To 显示名。
        assertEquals("", call.from)
        assertEquals("", call.to)
        assertEquals(0.0, call.startRel, 1e-3)
        assertEquals(2_000L, call.setupMs)
        assertNotNull(ready.setup)
        assertEquals(CALL_ID, ready.setup?.selectedAttempt?.callId)
        assertTrue(repository.scannedWith == listOf(false))
    }

    // ------------------------------------------------------------ 场景 2：sipTruncated 透传

    @Test
    fun `a truncated sip analysis flows through to ready with a warning`() {
        val repository = FakeVoipRtpRepository().apply { scanResult = scanResult() }
        val viewModel = viewModel(
            repository,
            coordinatorWithSession(),
            cache(),
            analysisSource = { analysis(sipTruncated = true) }
        )

        viewModel.load()

        val ready = ready(viewModel)
        assertTrue(ready.sipTruncated)
        assertTrue(
            "expected a truncation warning but was ${ready.warnings}",
            ready.warnings.any { it.contains("truncat", ignoreCase = true) }
        )
    }

    // ------------------------------------------------------------ 场景 3：会话失效

    @Test
    fun `closing the capture session returns the state to idle and clears playback`() {
        val repository = FakeVoipRtpRepository().apply {
            scanResult = scanResult(stream("s0"), stream("s1", fromCallee = true))
        }
        val coordinator = coordinatorWithSession()
        val viewModel = viewModel(repository, coordinator, cache())
        viewModel.load()
        viewModel.selectCall(ready(viewModel).calls.single().callId)
        assertNotNull(viewModel.playback.value)

        coordinator.invalidateSession()

        assertEquals(VoipCallsUiState.Idle, viewModel.state.value)
        assertNull(viewModel.playback.value)
    }

    @Test
    fun `bumping the analysis config version returns the state to idle`() {
        val repository = FakeVoipRtpRepository().apply { scanResult = scanResult(stream("s0")) }
        val coordinator = coordinatorWithSession()
        val viewModel = viewModel(repository, coordinator, cache())
        viewModel.load()
        assertTrue(viewModel.state.value is VoipCallsUiState.Ready)

        coordinator.bumpAnalysisConfigVersion()

        assertEquals(VoipCallsUiState.Idle, viewModel.state.value)
    }

    @Test
    fun `a filter revision change resets a filtered load but not an unfiltered one`() = runBlocking {
        val coordinator = coordinatorWithSession()
        val filtered = viewModel(FakeVoipRtpRepository(), coordinator, cache())
        filtered.load(limitToDisplayFilter = true)
        assertTrue(filtered.state.value is VoipCallsUiState.Ready)

        val unfiltered = viewModel(FakeVoipRtpRepository(), coordinator, cache())
        unfiltered.load()
        assertTrue(unfiltered.state.value is VoipCallsUiState.Ready)

        coordinator.applyUserFilter("ip.addr==10.0.0.1", coordinator.currentToken())

        assertEquals(VoipCallsUiState.Idle, filtered.state.value)
        assertTrue(unfiltered.state.value is VoipCallsUiState.Ready)
    }

    // ------------------------------------------------------------ 场景 4：mix 方向

    @Test
    fun `selectCall mixes forward on the left and reverse on the right`() {
        val repository = FakeVoipRtpRepository().apply {
            scanResult = scanResult(stream("s0"), stream("s1", fromCallee = true))
        }
        val viewModel = viewModel(repository, coordinatorWithSession(), cache())
        viewModel.load()
        val call = ready(viewModel).calls.single()
        val forward = call.streams.first { it.direction == RtpStreamDirection.FORWARD }.stream
        val reverse = call.streams.first { it.direction == RtpStreamDirection.REVERSE }.stream
        assertEquals("s0", forward.id)
        assertEquals("s1", reverse.id)

        viewModel.selectCall(call.callId)

        val request = repository.decodeRequests.single()
        assertEquals("s0", request.mix?.leftStreamId)
        assertEquals("s1", request.mix?.rightStreamId)
        assertEquals("absArrival", request.mix?.align)
        assertEquals(listOf("s0", "s1"), request.streamIds)
        assertTrue(request.dtmf)
        assertEquals(RtpTimingMode.JITTER, request.timing)
        assertEquals(SCAN_GENERATION, request.scanGeneration)
    }

    // ------------------------------------------------------------ 场景 5：没有会话

    @Test
    fun `a load without an open session stays idle and never scans`() {
        val repository = FakeVoipRtpRepository()
        val viewModel = viewModel(repository, coordinatorWithoutSession(), cache())

        viewModel.load()

        assertEquals(VoipCallsUiState.Idle, viewModel.state.value)
        assertEquals(0, repository.scanCalls)
    }

    // ------------------------------------------------------------ 场景 6：扫描报错

    @Test
    fun `a scan that reports an error becomes the error state`() {
        val repository = FakeVoipRtpRepository().apply {
            scanResult = scanResult(error = "staleScan")
        }
        val viewModel = viewModel(repository, coordinatorWithSession(), cache())

        viewModel.load()

        val state = viewModel.state.value
        assertTrue("expected Error but was $state", state is VoipCallsUiState.Error)
        assertEquals("staleScan", (state as VoipCallsUiState.Error).message)
    }

    // ------------------------------------------------------------ 场景 7：unsupported 仍要透出

    @Test
    fun `a call whose streams are all unsupported still publishes the unsupported list`() {
        val repository = FakeVoipRtpRepository().apply {
            scanResult = scanResult(stream("s0"), stream("s1", fromCallee = true))
            decodeResult = RtpDecodeResult(
                error = "",
                cancelled = false,
                items = emptyList(),
                unsupported = listOf(
                    RtpUnsupportedStream("s0", "unsupported"),
                    RtpUnsupportedStream("s1", "srtp")
                )
            )
        }
        val viewModel = viewModel(repository, coordinatorWithSession(), cache())
        viewModel.load()

        viewModel.selectCall(ready(viewModel).calls.single().callId)

        val playback = viewModel.playback.value
        assertNotNull(playback)
        assertEquals(listOf("s0", "s1"), playback?.unsupported?.map { it.streamId })
        assertTrue(playback?.items?.isEmpty() == true)
    }

    // ------------------------------------------------------------ 场景 8：分析缓存

    @Test
    fun `the communication analysis is reused until the session triple changes`() {
        var produced = 0
        val repository = FakeVoipRtpRepository().apply { scanResult = scanResult() }
        val coordinator = coordinatorWithSession()
        val viewModel = viewModel(
            repository,
            coordinator,
            cache(),
            analysisSource = {
                produced += 1
                analysis()
            }
        )

        viewModel.load()
        viewModel.load()

        assertEquals(1, produced)
        assertEquals(2, repository.scanCalls)

        coordinator.bumpAnalysisConfigVersion()
        viewModel.load()

        assertEquals(2, produced)
    }

    // ------------------------------------------------------------ 场景 9：过期结果

    @Test
    fun `a stale load never overwrites a newer ready`() {
        val repository = FakeVoipRtpRepository()
        val viewModel = viewModel(repository, coordinatorWithSession(), cache())
        repository.scanResponder = { call ->
            if (call == 1) {
                // 第一次加载：在自己的结果返回之前先让第二次加载完整跑完，
                // 于是第一次的结果「晚于」第二次返回，必须被丢弃。
                viewModel.load()
                scanResult(stream("s-first"))
            } else {
                scanResult(stream("s-second"))
            }
        }

        viewModel.load()

        val ready = ready(viewModel)
        assertEquals(2, repository.scanCalls)
        assertEquals("s-second", ready.calls.single().streams.single().stream.id)
    }

    // ------------------------------------------------------------ 场景 10：JSON 契约

    @Test
    fun `the decode contract carries mix and dtmf in both directions`() {
        val repository = RtpRepository(PacketRepository())

        val request = JSONObject(
            repository.buildDecodeRequest(
                RtpDecodeRequest(
                    scanGeneration = 7L,
                    streamIds = listOf("s0", "s1"),
                    timing = RtpTimingMode.JITTER,
                    jitterMs = 50,
                    mix = RtpMixRequest(leftStreamId = "s0", rightStreamId = "s1"),
                    dtmf = true
                )
            )
        )
        assertEquals("s0", request.getJSONObject("mix").getString("left"))
        assertEquals("s1", request.getJSONObject("mix").getString("right"))
        assertEquals("absArrival", request.getJSONObject("mix").getString("align"))
        assertTrue(request.getBoolean("dtmf"))

        // 没给 mix/dtmf 时不得写出这两个键（老调用方的请求形状不变）。
        val mono = JSONObject(
            repository.buildDecodeRequest(
                RtpDecodeRequest(
                    scanGeneration = 7L,
                    streamIds = listOf("s0"),
                    timing = RtpTimingMode.JITTER
                )
            )
        )
        assertFalse(mono.has("mix"))
        assertFalse(mono.has("dtmf"))

        val result = repository.parseDecodeResult(
            """
            {
              "schemaVersion": 1,
              "error": "",
              "cancelled": false,
              "items": [{
                "streamId": "s0",
                "wavPath": "/cache/s0.wav",
                "dtmf": [{
                  "digit": "5",
                  "atMs": 5000,
                  "durMs": 160,
                  "volume": 10,
                  "frame": 900
                }]
              }],
              "unsupported": [],
              "mix": {
                "wavPath": "/cache/mix.wav",
                "channels": 2,
                "sampleRate": 8000,
                "durationMs": 31000,
                "leftOffsetMs": 0,
                "rightOffsetMs": 180,
                "resampled": false,
                "peaksLeftPath": "/cache/s0.peaks",
                "peaksRightPath": "/cache/s1.peaks",
                "mapLeftPath": "/cache/s0.map",
                "mapRightPath": "/cache/s1.map"
              }
            }
            """.trimIndent()
        )
        val mix = result.mix
        assertNotNull(mix)
        assertEquals("/cache/mix.wav", mix?.wavPath)
        assertEquals(2, mix?.channels)
        assertEquals(8_000, mix?.sampleRate)
        assertEquals(31_000L, mix?.durationMs)
        assertEquals(0L, mix?.leftOffsetMs)
        assertEquals(180L, mix?.rightOffsetMs)
        assertFalse(mix?.resampled == true)
        assertEquals("/cache/s0.peaks", mix?.peaksLeftPath)
        assertEquals("/cache/s1.map", mix?.mapRightPath)
        val event = result.items.single().dtmf.single()
        assertEquals("5", event.digit)
        assertEquals(5_000L, event.atMs)
        assertEquals(160L, event.durMs)
        assertEquals(10, event.volume)
        assertEquals(900L, event.frame)

        // 容忍缺失：不带 mix / dtmf 的响应照常解析（老版本原生层）。
        val older = repository.parseDecodeResult("""{"items":[{"streamId":"s0"}]}""")
        assertNull(older.mix)
        assertTrue(older.items.single().dtmf.isEmpty())
    }

    // ---- helpers ----------------------------------------------------------

    private fun cache(): RtpMediaCache = RtpMediaCache(File(temporaryFolder.root, "rtp"))

    /**
     * 造一个 ViewModel。`analysisSource` 默认给一条标准呼叫的通信分析夹具——
     * 走默认的 `packetRepository.buildCommunicationAnalysis()` 只会拿到空分析
     * （JVM 里没有原生会话），那对关联路径没有意义。
     */
    private fun viewModel(
        repository: RtpRepository,
        coordinator: CaptureSessionCoordinator = coordinatorWithoutSession(),
        mediaCache: RtpMediaCache? = null,
        analysisSource: (suspend () -> CommunicationAnalysis)? = { analysis() },
        fromToProvider: (suspend (List<String>) -> Map<String, Pair<String, String>>)? = null
    ): VoipCallsViewModel = VoipCallsViewModel(
        rtpRepository = repository,
        packetRepository = PacketRepository(),
        sessionCoordinator = coordinator,
        ioDispatcher = Dispatchers.Unconfined,
        externalScope = CoroutineScope(Dispatchers.Unconfined),
        mediaCache = mediaCache,
        analysisSource = analysisSource,
        fromToProvider = fromToProvider
    )

    private fun ready(viewModel: VoipCallsViewModel): VoipCallsUiState.Ready {
        val state = viewModel.state.value
        assertTrue("expected Ready but was $state", state is VoipCallsUiState.Ready)
        return state as VoipCallsUiState.Ready
    }

    /** 没有打开任何会话的协调器：只用来驱动失效规则。 */
    private fun coordinatorWithoutSession(): CaptureSessionCoordinator =
        CaptureSessionCoordinator(
            dataSource = AgentToolTestHarness.FakeSource(FRAME_COUNT),
            fingerprintDispatcher = Dispatchers.Unconfined,
            nativeDispatcher = Dispatchers.Unconfined
        )

    /** 打开了一个假会话的协调器：`applyUserFilter` 会自增 `filterRevision`。 */
    private fun coordinatorWithSession(): CaptureSessionCoordinator {
        val source = AgentToolTestHarness.FakeSource(FRAME_COUNT)
        val file = File.createTempFile("voip-calls-viewmodel-test", ".pcap")
        file.writeText("capture")
        source.switchSession(SESSION_HANDLE, file)
        val coordinator = CaptureSessionCoordinator(
            dataSource = source,
            fingerprintDispatcher = Dispatchers.Unconfined,
            nativeDispatcher = Dispatchers.Unconfined
        )
        coordinator.onSessionOpened(checkNotNull(source.currentFile()))
        file.delete()
        return coordinator
    }

    private companion object {
        const val FRAME_COUNT = 10
        const val SESSION_HANDLE = 1L
        const val SCAN_GENERATION = 7L
    }
}

/**
 * 真的 [RtpRepository] 的假实现：`RtpRepository` 被打开成 `open` 就是为了
 * JVM 单测能在不触碰 JNI 的前提下决定扫描/解码的返回值与时序。
 */
private class FakeVoipRtpRepository : RtpRepository(PacketRepository()) {

    /** 默认扫描返回值；[scanResponder] 为 null 时使用。 */
    var scanResult: RtpScanResult = scanResult()

    /** 按调用序号（从 1 起）决定扫描返回值；用于制造过期结果。 */
    var scanResponder: ((call: Int) -> RtpScanResult)? = null

    /** 默认解码返回值。 */
    var decodeResult: RtpDecodeResult = RtpDecodeResult("", false, emptyList(), emptyList())

    var scanCalls: Int = 0
        private set
    val scannedWith = mutableListOf<Boolean>()
    val decodeRequests = mutableListOf<RtpDecodeRequest>()

    override fun scanRtpStreams(
        limitToDisplayFilter: Boolean,
        onProgress: ((RtpProgress) -> Boolean)?
    ): RtpScanResult {
        scanCalls += 1
        scannedWith += limitToDisplayFilter
        return scanResponder?.invoke(scanCalls) ?: scanResult
    }

    override fun decodeAudio(
        request: RtpDecodeRequest,
        outDir: File,
        onProgress: ((RtpProgress) -> Boolean)?
    ): RtpDecodeResult {
        decodeRequests += request
        return decodeResult
    }
}

// ---------------------------------------------------------------- 夹具

private const val CAPTURE_START = 1_700_000_000.0
private const val CALL_ID = "call-1"
private const val CALLER_ADDRESS = "192.0.2.1"
private const val CALLEE_ADDRESS = "192.0.2.2"
private const val CALLER_MEDIA_PORT = 4000
private const val CALLEE_MEDIA_PORT = 5000
private const val CALLER_TAG = "caller-tag"
private const val CALLEE_TAG = "callee-tag"
private const val VIA_BRANCH = "z9hG4bK-call-1-1"

/** 相对抓包起点的秒数 → 绝对 epoch 秒（原生层的 `time` 就是绝对 epoch 秒）。 */
private fun at(relativeSeconds: Double): Double = CAPTURE_START + relativeSeconds

/**
 * 一次标准呼叫的 SIP 消息：INVITE（带 offer SDP）→ 200 OK（带 answer SDP）→ ACK。
 *
 * 交给真实的 `SipTransactionCorrelator` 之后会得到一条 dialog：主叫侧 offer 是
 * `192.0.2.1:4000`，被叫 answer 是 `192.0.2.2:5000`，状态 [VoipCallState.IN_CALL]。
 * 排序按时间给出（correlator 自己也会排序）。
 */
private fun standardSipMessages(callId: String = CALL_ID): List<SipMessage> {
    val offer = sdp(10, CALLER_ADDRESS, CALLER_MEDIA_PORT)
    val answer = sdp(14, CALLEE_ADDRESS, CALLEE_MEDIA_PORT)
    return listOf(
        SipMessage(
            frameNumber = 10,
            time = at(0.0),
            source = CALLER_ADDRESS,
            destination = CALLEE_ADDRESS,
            sourcePort = 5060,
            destinationPort = 5060,
            method = "INVITE",
            callId = callId,
            cSeqNumber = 1,
            cSeqMethod = "INVITE",
            viaBranch = VIA_BRANCH,
            fromTag = CALLER_TAG,
            sdp = offer
        ),
        SipMessage(
            frameNumber = 14,
            time = at(2.0),
            source = CALLEE_ADDRESS,
            destination = CALLER_ADDRESS,
            sourcePort = 5060,
            destinationPort = 5060,
            status = "200 OK",
            callId = callId,
            cSeqNumber = 1,
            cSeqMethod = "INVITE",
            viaBranch = VIA_BRANCH,
            fromTag = CALLER_TAG,
            toTag = CALLEE_TAG,
            sdp = answer
        ),
        SipMessage(
            frameNumber = 16,
            time = at(2.1),
            source = CALLER_ADDRESS,
            destination = CALLEE_ADDRESS,
            sourcePort = 5060,
            destinationPort = 5060,
            method = "ACK",
            callId = callId,
            cSeqNumber = 1,
            cSeqMethod = "ACK",
            viaBranch = "z9hG4bK-call-1-ack",
            fromTag = CALLER_TAG,
            toTag = CALLEE_TAG
        )
    )
}

/** 通信分析夹具：只有 `sipMessages` 参与关联（`sipDialogs` 由 ViewModel 现算）。 */
private fun analysis(
    sipTruncated: Boolean = false,
    sipMessages: List<SipMessage> = standardSipMessages()
): CommunicationAnalysis = CommunicationAnalysis(
    sipMessages = sipMessages,
    sipTotal = sipMessages.size,
    sipTruncated = sipTruncated
)

private fun sdp(frame: Long, address: String, port: Int?): SdpMediaSummary = SdpMediaSummary(
    frameNumber = frame,
    connectionAddress = address,
    mediaType = "audio",
    mediaPort = port,
    mediaProtocol = "RTP/AVP",
    formats = listOf("8"),
    codecs = listOf("PCMA")
)

/** 造一个 [RtpScanResult]；[streams] 为空时表示「没有流」。 */
private fun scanResult(
    vararg streams: RtpStream,
    cancelled: Boolean = false,
    error: String = ""
): RtpScanResult = RtpScanResult(
    schemaVersion = 1,
    error = error,
    cancelled = cancelled,
    scanGeneration = 7L,
    framesScanned = 100L,
    heuristicEnabled = false,
    streamsTruncated = false,
    streams = streams.toList()
)

/**
 * 造一条 RTP 流。[firstAbsEpochUs] 与 [startRel] 始终自洽
 * （`firstAbsEpochUs / 1e6 - startRel == CAPTURE_START`），这正是联接器推导抓包起点的依据。
 *
 * 默认方向是主叫 → 被叫（`192.0.2.1:4000` → `192.0.2.2:5000`），[fromCallee] 时反向。
 */
private fun stream(
    id: String,
    fromCallee: Boolean = false,
    startRel: Double = 1.0,
    codec: String = "g711A",
    decodable: RtpDecodability = RtpDecodability.YES
): RtpStream = RtpStream(
    id = id,
    src = if (fromCallee) CALLEE_ADDRESS else CALLER_ADDRESS,
    srcPort = if (fromCallee) CALLEE_MEDIA_PORT else CALLER_MEDIA_PORT,
    dst = if (fromCallee) CALLER_ADDRESS else CALLEE_ADDRESS,
    dstPort = if (fromCallee) CALLER_MEDIA_PORT else CALLEE_MEDIA_PORT,
    ssrc = 0x0badf00dL,
    ssrcHex = "0badf00d",
    pt = 8,
    codec = codec,
    codecSource = RtpCodecSource.SDP,
    clockRate = 8000,
    setupFrame = 0L,
    setupMethod = "sdp",
    isSrtp = false,
    packets = 50L,
    expected = 50L,
    lost = 0L,
    lostPct = 0.0,
    seqErrors = 0L,
    outOfOrder = 0L,
    truncated = 0L,
    problem = false,
    minDeltaMs = 20.0,
    meanDeltaMs = 20.0,
    maxDeltaMs = 20.0,
    maxDeltaFrame = 50L,
    minJitterMs = 0.0,
    meanJitterMs = 0.0,
    maxJitterMs = 0.0,
    jitterAvailable = true,
    maxSkewMs = 0.0,
    bytes = 8000L,
    firstFrame = 40L,
    lastFrame = 90L,
    startRel = startRel,
    endRel = startRel + 10.0,
    firstAbsEpochUs = ((CAPTURE_START + startRel) * 1_000_000.0).toLong(),
    ptsSeen = listOf(8),
    decodable = decodable,
    decodableReason = "",
    primaryPayloadType = 8
)
