// Copyright (c) 2026 cheig
// LayerAnalyzer - https://github.com/cheig/LayerAnalyzer
// Licensed under GNU GPL version 3; see LICENSE.

package com.example.layanalyzer.data

import com.example.layanalyzer.NativeEngine
import com.example.layanalyzer.model.DisplayFilterResult
import com.example.layanalyzer.model.FileSessionInfo
import com.example.layanalyzer.model.RTP_MIX_ALIGN_ABS_ARRIVAL
import com.example.layanalyzer.model.RtpCodecCatalog
import com.example.layanalyzer.model.RtpCodecRoute
import com.example.layanalyzer.model.RtpDecodeRequest
import com.example.layanalyzer.model.RtpMixRequest
import com.example.layanalyzer.model.RtpTimingMode
import com.example.layanalyzer.model.RtpUnsupportedReason
import org.json.JSONArray
import org.json.JSONObject
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Rule
import org.junit.Test
import org.junit.rules.TemporaryFolder
import java.io.File
import java.nio.ByteBuffer
import java.nio.ByteOrder

/**
 * RTP4-KT-02 的解码路由单测（纯 JVM）。
 *
 * 覆盖三件事：
 *
 *  1. **路由表逐项**：NATIVE / MEDIACODEC / UNSUPPORTED 三类编码，含 `G726-16`、
 *     `AAL2-G726-24` 这些还没进 [RtpCodecCatalog.entries] 的规范 ID，以及未知名字。
 *  2. **`UNSUPPORTED` 一次 JNI 都不调**：这里不是断言「纯函数返回了 UNSUPPORTED」，
 *     而是给 [RtpRepository] 注入一个记账用的 [RtpNativeBridge]，直接数调用次数。
 *     为此注入的是一个非 0 的会话句柄（`PacketRepository` 在 JVM 上恒为 0，用它
 *     会让 `decodeAudio` 在「No capture is open.」处提前返回，使断言变成同义反复）。
 *  3. **既有调用点的形状没变**：不填 `streamCodecs` 的请求仍然只调一次
 *     `decodeRtpAudio`，带 `mix` 的请求整单走原生（卡片第 4 条）。
 */
class RtpCodecRouteTest {

    @get:Rule
    val temporaryFolder = TemporaryFolder()

    // ------------------------------------------------------------- 路由表

    @Test
    fun `the route table matches the card for every audio family`() {
        val native = listOf(
            "g711A", "g711U", "L16", "g722", "g729",
            // README §4.3 的 G.726 两个族：原生解码，但还没进 entries。
            "G726-16", "G726-24", "G726-32", "G726-40",
            "AAL2-G726-16", "AAL2-G726-24", "AAL2-G726-32", "AAL2-G726-40",
            // iLBC 同样由原生解码（m4.md NAT-06 第 5 条）。
            "iLBC"
        )
        val mediaCodec = listOf("AMR", "AMR-WB", "opus")

        native.forEach { codec ->
            assertEquals(codec, RtpCodecRoute.NATIVE, RtpCodecCatalog.route(codec))
        }
        mediaCodec.forEach { codec ->
            assertEquals(codec, RtpCodecRoute.MEDIACODEC, RtpCodecCatalog.route(codec))
        }
    }

    @Test
    fun `the route table is case insensitive and closes on everything else`() {
        assertEquals(RtpCodecRoute.NATIVE, RtpCodecCatalog.route("g711a"))
        assertEquals(RtpCodecRoute.NATIVE, RtpCodecCatalog.route("G711A"))
        assertEquals(RtpCodecRoute.NATIVE, RtpCodecCatalog.route("g726-32"))
        assertEquals(RtpCodecRoute.NATIVE, RtpCodecCatalog.route("aal2-g726-24"))
        assertEquals(RtpCodecRoute.NATIVE, RtpCodecCatalog.route("ilbc"))
        assertEquals(RtpCodecRoute.MEDIACODEC, RtpCodecCatalog.route("amr-wb"))
        assertEquals(RtpCodecRoute.MEDIACODEC, RtpCodecCatalog.route("OPUS"))
        // 前后空白也是同一个名字。
        assertEquals(RtpCodecRoute.MEDIACODEC, RtpCodecCatalog.route(" opus "))

        assertEquals(RtpCodecRoute.UNSUPPORTED, RtpCodecCatalog.route("H264"))
        assertEquals(RtpCodecRoute.UNSUPPORTED, RtpCodecCatalog.route("H265"))
        assertEquals(RtpCodecRoute.UNSUPPORTED, RtpCodecCatalog.route("nonsense"))
        assertEquals(RtpCodecRoute.UNSUPPORTED, RtpCodecCatalog.route(""))
        assertEquals(RtpCodecRoute.UNSUPPORTED, RtpCodecCatalog.route("   "))
        assertEquals(RtpCodecRoute.UNSUPPORTED, RtpCodecCatalog.route("telephone-event"))
    }

    @Test
    fun `every catalog entry carries the route the table gives it`() {
        RtpCodecCatalog.entries.forEach { entry ->
            assertEquals(entry.id, entry.route, RtpCodecCatalog.route(entry.id))
        }
        // RTP4-KT-05 宽化了 idSupported：它现在的语义是「本 App 设计上支持解码」，
        // 由运行时的 getRtpCodecCapabilities() 回答「这个构建有没有编进来」。
        // AMR 走 MediaCodec，所以两个字段一致地都是「支持」。
        val amr = requireNotNull(RtpCodecCatalog.byId("AMR"))
        assertEquals(true, amr.idSupported)
        assertEquals(RtpCodecRoute.MEDIACODEC, amr.route)
    }

    // ------------------------------------------------- 路由到 JNI 的调用次数

    @Test
    fun `unsupported codecs never reach any native entry point`() {
        val bridge = CountingNativeBridge()
        val repository = repository(bridge)

        val result = repository.decodeAudio(
            request = request(
                streamIds = listOf("s0", "s1"),
                codecs = mapOf("s0" to "H264", "s1" to "not-a-codec")
            ),
            outDir = temporaryFolder.newFolder("unsupported")
        )

        assertEquals("no JNI may be called for an unsupported codec", 0, bridge.totalCalls)
        assertTrue(result.isSuccess)
        assertTrue(result.items.isEmpty())
        assertEquals(listOf("s0", "s1"), result.unsupported.map { it.streamId })
        assertEquals(
            List(2) { RtpUnsupportedReason.UNSUPPORTED.wireValue },
            result.unsupported.map { it.reason }
        )
    }

    @Test
    fun `an unsupported codec does not drag its native neighbours with it`() {
        val bridge = CountingNativeBridge()
        val repository = repository(bridge)

        val result = repository.decodeAudio(
            request = request(
                streamIds = listOf("s0", "s1", "s2"),
                codecs = mapOf("s1" to "H265")
            ),
            outDir = temporaryFolder.newFolder("mixed")
        )

        assertTrue(result.isSuccess)
        // 只有原生路径那一次调用，且请求里没有 s1。
        assertEquals(1, bridge.decodeCalls.size)
        assertEquals(0, bridge.extractCalls.size)
        assertEquals(0, bridge.renderCalls.size)
        assertEquals(listOf("s0", "s2"), bridge.streamsOfCall(0))
        assertEquals(listOf("s1"), result.unsupported.map { it.streamId })
    }

    @Test
    fun `a request without codecs keeps the pre KT 02 behaviour`() {
        val bridge = CountingNativeBridge()
        val repository = repository(bridge)

        val result = repository.decodeAudio(
            request = request(streamIds = listOf("s0", "s1", "s2")),
            outDir = temporaryFolder.newFolder("legacy")
        )

        assertTrue(result.isSuccess)
        assertEquals(1, bridge.decodeCalls.size)
        assertEquals(listOf("s0", "s1", "s2"), bridge.streamsOfCall(0))
        assertTrue(result.unsupported.isEmpty())
    }

    @Test
    fun `a mix request keeps every stream on the native path`() {
        val bridge = CountingNativeBridge()
        val repository = repository(bridge)

        val result = repository.decodeAudio(
            request = request(
                streamIds = listOf("s0", "s1"),
                // 两路都是 MEDIACODEC 编码：按卡片第 4 条它们必须先由调用方渲染成
                // WAV，再用 leftWav/rightWav 混音，所以这里不做三段提取。
                codecs = mapOf("s0" to "AMR", "s1" to "opus"),
                mix = RtpMixRequest(
                    leftStreamId = "s0",
                    rightStreamId = "s1",
                    leftWav = "/cache/s0.wav",
                    rightWav = "/cache/s1.wav"
                )
            ),
            outDir = temporaryFolder.newFolder("wav-mix")
        )

        assertTrue(result.isSuccess)
        assertEquals(1, bridge.decodeCalls.size)
        assertEquals(0, bridge.extractCalls.size)
        assertEquals(0, bridge.renderCalls.size)
        assertEquals(listOf("s0", "s1"), bridge.streamsOfCall(0))
        val mix = JSONObject(bridge.decodeCalls.single()).getJSONObject("mix")
        assertEquals("/cache/s0.wav", mix.getString("leftWav"))
        assertEquals("/cache/s1.wav", mix.getString("rightWav"))
    }

    @Test
    fun `a mix request whose streams are all unsupported calls nothing either`() {
        val bridge = CountingNativeBridge()
        val repository = repository(bridge)

        val result = repository.decodeAudio(
            request = request(
                streamIds = listOf("s0", "s1"),
                codecs = mapOf("s0" to "H264", "s1" to "PS"),
                mix = RtpMixRequest(leftStreamId = "s0", rightStreamId = "s1")
            ),
            outDir = temporaryFolder.newFolder("unsupported-mix")
        )

        assertEquals(0, bridge.totalCalls)
        assertEquals(2, result.unsupported.size)
    }

    @Test
    fun `no session means no native call and the usual message`() {
        val bridge = CountingNativeBridge()
        val repository = RtpRepository(FakeSession(0L), bridge)

        val result = repository.decodeAudio(
            request = request(streamIds = listOf("s0"), codecs = mapOf("s0" to "g711A")),
            outDir = temporaryFolder.newFolder("no-session")
        )

        assertEquals(0, bridge.totalCalls)
        assertEquals("No capture is open.", result.error)
    }

    // --------------------------------------------------------- 请求 / mime

    @Test
    fun `the mix request carries the wav fields only when they are given`() {
        val repository = repository(CountingNativeBridge())

        val bare = JSONObject(
            repository.buildDecodeRequest(
                request(
                    streamIds = listOf("s0", "s1"),
                    mix = RtpMixRequest(leftStreamId = "s0", rightStreamId = "s1")
                )
            )
        ).getJSONObject("mix")
        assertEquals("s0", bare.getString("left"))
        assertEquals("s1", bare.getString("right"))
        assertEquals(RTP_MIX_ALIGN_ABS_ARRIVAL, bare.getString("align"))
        assertTrue(!bare.has("leftWav"))
        assertTrue(!bare.has("rightWav"))
        assertTrue(!bare.has("leftPeaks"))
        assertTrue(!bare.has("rightMap"))

        val rendered = JSONObject(
            repository.buildDecodeRequest(
                request(
                    streamIds = listOf("s0", "s1"),
                    mix = RtpMixRequest(
                        leftStreamId = "s0",
                        rightStreamId = "s1",
                        leftWav = "/cache/s0.wav",
                        rightWav = "/cache/s1.wav",
                        leftPeaks = "/cache/s0.peaks",
                        leftMap = "/cache/s0.map",
                        rightPeaks = "/cache/s1.peaks",
                        rightMap = "/cache/s1.map"
                    )
                )
            )
        ).getJSONObject("mix")
        assertEquals("/cache/s0.wav", rendered.getString("leftWav"))
        assertEquals("/cache/s1.wav", rendered.getString("rightWav"))
        assertEquals("/cache/s0.peaks", rendered.getString("leftPeaks"))
        assertEquals("/cache/s0.map", rendered.getString("leftMap"))
        assertEquals("/cache/s1.peaks", rendered.getString("rightPeaks"))
        assertEquals("/cache/s1.map", rendered.getString("rightMap"))
    }

    @Test
    fun `the decode request lists only the streams it was handed`() {
        val repository = repository(CountingNativeBridge())

        val json = JSONObject(
            repository.buildDecodeRequest(
                request(streamIds = listOf("s0", "s1", "s2")),
                listOf("s0", "s2")
            )
        )

        assertEquals(listOf("s0", "s2"), json.streams())
        assertEquals(7L, json.getLong("scanGeneration"))
        assertEquals("jitter", json.getString("timing"))
    }

    @Test
    fun `the native mime is mapped onto the platform constants`() {
        val repository = repository(CountingNativeBridge())

        // AMR-NB 是唯一不一致的一个：原生契约是 audio/amr，平台登记为 audio/3gpp。
        assertEquals("audio/3gpp", repository.platformAudioMime("audio/amr"))
        assertEquals("audio/3gpp", repository.platformAudioMime("AUDIO/AMR"))
        // AMR-WB 与 Opus 本来就是一致的，仍然显式映射，防止两边悄悄漂移。
        assertEquals("audio/amr-wb", repository.platformAudioMime("audio/amr-wb"))
        assertEquals("audio/opus", repository.platformAudioMime("audio/opus"))
        // 表外的 mime 原样透传，不猜。
        assertEquals("audio/whatever", repository.platformAudioMime("audio/whatever"))
    }

    @Test
    fun `a media codec stream is routed to the extractor and not to the native decoder`() {
        // MEDIACODEC 三段里只有第一段能在 JVM 上断言：`extractRtpCodecFrames` 由 fake
        // 回答；`MediaCodecAudioDecoder` 在 JVM 单测里连第一条日志都打不出来
        // （`android.util.Log` 是 not mocked 的桩），所以「解码出来的 PCM 渲染成
        // WAV」这一段只能由设备上的 RtpMediaCodecRenderTest / RTP4-QA-01 覆盖。
        // 这里断言的是本卡真正负责的东西：编码为 opus 的流**走的是提取器**，
        // 请求带对了代次与流 id，而且没有被误送给原生的 `decodeRtpAudio`。
        val dir = temporaryFolder.newFolder("media-codec")
        val bridge = CountingNativeBridge().apply {
            extractResponse = codecFramesResponse("s0", dir, mime = "audio/opus", sampleRate = 48_000)
        }
        val repository = repository(bridge)

        repository.decodeAudio(
            request = request(streamIds = listOf("s0"), codecs = mapOf("s0" to "opus")),
            outDir = temporaryFolder.newFolder("media-codec-out")
        )

        assertEquals(1, bridge.extractCalls.size)
        val extract = JSONObject(bridge.extractCalls.single())
        assertEquals(7L, extract.getLong("scanGeneration"))
        assertEquals("s0", extract.getString("streamId"))
        // 请求只有这两个键：打包模式（amrMode）交给原生层自动探测。
        assertEquals(2, extract.length())
        assertTrue(
            "an opus stream must not be handed to the native decoder",
            bridge.decodeCalls.isEmpty()
        )
    }

    // ---------------------------------------------------------------- 工具

    /** 一份最小的 `extractRtpCodecFrames` 成功应答，含真实的 `.frames`/`.fidx`。 */
    private fun codecFramesResponse(
        streamId: String,
        outDir: File,
        mime: String,
        sampleRate: Int
    ): String {
        val frames = File(outDir, "$streamId.frames").apply { writeBytes(ByteArray(4)) }
        val index = File(outDir, "$streamId.fidx").apply { writeBytes(oneEntryFidx()) }
        return JSONObject()
            .put("schemaVersion", 1)
            .put("error", "")
            .put("cancelled", false)
            .put("framesPath", frames.absolutePath)
            .put("indexPath", index.absolutePath)
            .put("codec", mime)
            .put("sampleRate", sampleRate)
            .put("channels", 1)
            .put("mime", mime)
            .put("csd", JSONArray())
            .put("frameCount", 1)
            .toString()
    }

    /** `"FID1"`、`u32 count = 1`，再一条 33 字节记录（RTP4-NAT-06 的磁盘布局）。 */
    private fun oneEntryFidx(): ByteArray =
        ByteBuffer.allocate(8 + 33).order(ByteOrder.LITTLE_ENDIAN)
            .put("FID1".toByteArray(Charsets.US_ASCII))
            .putInt(1)
            .putLong(0L)      // offset
            .putInt(4)        // length
            .putInt(1)        // frame
            .putLong(0L)      // extTs
            .putDouble(0.0)   // arrivalRel
            .put(0x00.toByte())  // flags
            .array()


    private fun repository(bridge: RtpNativeBridge): RtpRepository =
        RtpRepository(FakeSession(SESSION_HANDLE), bridge)

    private fun request(
        streamIds: List<String>,
        codecs: Map<String, String> = emptyMap(),
        mix: RtpMixRequest? = null
    ): RtpDecodeRequest = RtpDecodeRequest(
        scanGeneration = 7L,
        streamIds = streamIds,
        timing = RtpTimingMode.JITTER,
        jitterMs = 50,
        mix = mix,
        streamCodecs = codecs
    )

    private fun JSONObject.streams(): List<String> {
        val array = getJSONArray("streams")
        return List(array.length()) { array.getString(it) }
    }

    private fun CountingNativeBridge.streamsOfCall(index: Int): List<String> =
        JSONObject(decodeCalls[index]).streams()

    /**
     * 记账用的 native 桥：只数调用、按 [decodeResponse]/[extractResponse] 回答。
     * 任何一次调用都会被断言抓住，所以「没调用」是真的没调用。
     */
    private class CountingNativeBridge(
        private val decodeResponse: String =
            """{"schemaVersion":1,"error":"","cancelled":false,"items":[],"unsupported":[]}"""
    ) : RtpNativeBridge {
        val decodeCalls = mutableListOf<String>()
        val extractCalls = mutableListOf<String>()
        val renderCalls = mutableListOf<String>()

        /** 默认回 `nativeDecode`：走到这里就说明路由把它送错了地方。 */
        var extractResponse: String = """{"schemaVersion":1,"error":"nativeDecode"}"""

        val totalCalls: Int
            get() = decodeCalls.size + extractCalls.size + renderCalls.size

        override fun decodeRtpAudio(
            sessionPtr: Long,
            requestJson: String,
            outDir: String,
            progress: NativeEngine.RtpProgressCallback?
        ): String {
            decodeCalls += requestJson
            return decodeResponse
        }

        override fun extractRtpCodecFrames(
            sessionPtr: Long,
            requestJson: String,
            outDir: String,
            progress: NativeEngine.RtpProgressCallback?
        ): String {
            extractCalls += requestJson
            return extractResponse
        }

        override fun renderRtpAudioFromPcm(
            sessionPtr: Long,
            requestJson: String,
            outDir: String
        ): String {
            renderCalls += requestJson
            return """{"schemaVersion":1,"error":"unreachable"}"""
        }
    }

    /** 会话句柄必须是非 0，否则 `decodeAudio` 在取句柄处就返回了。 */
    private class FakeSession(private val handle: Long) : CaptureSessionDataSource {
        override fun currentSessionHandle(): Long = handle

        override fun currentFile(): FileSessionInfo? = null

        override fun getFrameCount(): Int = 0

        override fun getVisibleFrameCount(): Int = 0

        override fun getAppliedDisplayFilter(): String = ""

        override fun applyDisplayFilter(
            filter: String,
            expectedSessionHandle: Long
        ): DisplayFilterResult = DisplayFilterResult(success = true, filteredCount = 0)

        override fun validateDisplayFilter(filter: String): Result<Unit> = Result.success(Unit)

        override fun cancelLongRunningOperations() = Unit
    }

    private companion object {
        const val SESSION_HANDLE = 4_242L
    }
}
