package com.example.layanalyzer.data

import org.json.JSONObject
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test
import java.util.Base64

/**
 * RTP5-KT-02：`exportRtpVideo` 的 Kotlin 侧契约单测（不碰 JNI）。
 *
 * 请求形状与返回解析是冻结契约（`RtpJni.cpp` 的 `Java_.._exportRtpVideo` 与
 * `task_rtp_m5_video.md` §3.1），这里逐字段钉住。两条规则最要紧：
 *
 *  - **可选字段缺省不等于发一个默认值**。原生层用「键在不在」区分「调用方说了」
 *    与「调用方没说」（`has_ts_rate`、`param_sets_present_in_stream`），所以
 *    `null` 与 `false`/`0` 必须是两种不同的请求。
 *  - **原生把结果的每个键都预置成中性值**，解析器必须容忍那一套形状（最刺眼的是
 *    `csd` 里三个 `JSONObject.NULL`）。
 */
class RtpVideoExportTest {

    private val repository = RtpRepository(PacketRepository())

    @Test
    fun `request carries the five required keys and nothing else`() {
        val request = JSONObject(
            repository.buildVideoExportRequest(
                scanGeneration = 7L,
                streamId = "s4",
                codec = "H264",
                startAtKeyframe = true,
                dropCorrupt = false
            )
        )
        assertEquals(5, request.length())
        assertEquals(7L, request.getLong("scanGeneration"))
        assertEquals("s4", request.getString("streamId"))
        assertEquals("H264", request.getString("codec"))
        assertTrue(request.getBoolean("startAtKeyframe"))
        assertFalse(request.getBoolean("dropCorrupt"))
        // 四个可选字段一个都不许出现。
        listOf("paramSets", "tsRate", "donDiff", "paramSetsPresentInStream").forEach { key ->
            assertFalse("$key must be omitted when the caller did not provide it", request.has(key))
        }
    }

    @Test
    fun `omitting paramSetsPresentInStream is not the same as sending false`() {
        // 缺省：调用方不知道。原生层按 false 处理，但**这是它的默认**，不是本层的断言。
        val omitted = JSONObject(
            repository.buildVideoExportRequest(1L, "s0", "H265", true, false)
        )
        assertFalse(omitted.has("paramSetsPresentInStream"))

        // 显式 false：KT-00 断言过这条流的带内没有参数集，原生层据此把「带内有」
        // 也算成一种来源。两者在原生层的判断里是同一件事的反面，必须是两个请求。
        val explicit = JSONObject(
            repository.buildVideoExportRequest(
                scanGeneration = 1L,
                streamId = "s0",
                codec = "H265",
                startAtKeyframe = true,
                dropCorrupt = false,
                paramSetsPresentInStream = false
            )
        )
        assertTrue(explicit.has("paramSetsPresentInStream"))
        assertFalse(explicit.getBoolean("paramSetsPresentInStream"))
    }

    @Test
    fun `the optional scalars appear only when they are given`() {
        val request = JSONObject(
            repository.buildVideoExportRequest(
                scanGeneration = 2L,
                streamId = "s0",
                codec = "H265",
                startAtKeyframe = false,
                dropCorrupt = true,
                tsRate = 90000,
                donDiff = 0,
                paramSetsPresentInStream = true
            )
        )
        assertEquals(90000, request.getInt("tsRate"))
        // donDiff 的 0 与「没说」是两件事：0 也要写出去。
        assertTrue(request.has("donDiff"))
        assertEquals(0, request.getInt("donDiff"))
        assertTrue(request.getBoolean("paramSetsPresentInStream"))
        assertFalse(request.getBoolean("startAtKeyframe"))
        assertTrue(request.getBoolean("dropCorrupt"))
    }

    @Test
    fun `parameter sets are written as base64 arrays only when there are any`() {
        val sets = VideoParamSets(
            sps = listOf(byteArrayOf(0x67, 0x64, 0x00, 0x1F)),
            pps = listOf(byteArrayOf(0x68, 0xEB.toByte())),
            vps = emptyList(),
            packetizationMode = 1,
            profileLevelId = "64001F",
            donDiff = null
        )
        val request = JSONObject(
            repository.buildVideoExportRequest(
                scanGeneration = 3L,
                streamId = "s0",
                codec = "H264",
                startAtKeyframe = true,
                dropCorrupt = false,
                paramSets = sets,
                // 单测里的 Base64 用 java.util 的：本模块的 android.util.Base64 是
                // not mocked 的桩，碰一下就抛（接缝存在的理由）。
                encode = { Base64.getEncoder().encodeToString(it) }
            )
        )
        val encoded = request.getJSONObject("paramSets")
        assertEquals("Z2QAHw==", encoded.getJSONArray("sps").getString(0))
        assertEquals("aOs=", encoded.getJSONArray("pps").getString(0))
        // 三个键永远都在（原生按数组处理，空数组就是「没有」），但**不许**塞空串：
        // 原生对空串/非法 Base64 是拒绝整个请求，而不是忽略那一项。
        assertEquals(0, encoded.getJSONArray("vps").length())
    }

    @Test
    fun `an empty parameter set group is omitted rather than sent empty`() {
        val empty = VideoParamSets(
            sps = emptyList(),
            pps = emptyList(),
            vps = emptyList(),
            packetizationMode = null,
            profileLevelId = null,
            donDiff = null
        )
        val request = JSONObject(
            repository.buildVideoExportRequest(
                scanGeneration = 3L,
                streamId = "s0",
                codec = "H264",
                startAtKeyframe = true,
                dropCorrupt = false,
                paramSets = empty,
                encode = { Base64.getEncoder().encodeToString(it) }
            )
        )
        // 空组与「没有 SDP 参数集」对原生层是同一件事，写出去只是噪声。
        assertFalse(request.has("paramSets"))
    }

    @Test
    fun `a zero length entry does not make the group non empty`() {
        val result = VideoParamSets(
            sps = listOf(ByteArray(0)),
            pps = emptyList(),
            vps = emptyList(),
            packetizationMode = null,
            profileLevelId = null,
            donDiff = null
        )
        assertFalse(result.hasAnyParameterSet())
    }

    @Test
    fun `a full success response parses every field of the frozen json`() {
        val result = repository.parseVideoExportResult(
            """
            {"schemaVersion":1,"error":"","cancelled":false,
             "esPath":"/cache/rtp/1/2/s4.h264","indexPath":"/cache/rtp/1/2/s4.vidx",
             "codec":"H264","width":1280,"height":720,"profile":"High","level":"3.1",
             "csd":{"sps":"Z0LAHtk=","pps":"aM4BQA==","vps":null},
             "frames":900,"keyframes":30,"corruptFrames":2,"firstKeyframeIndex":0,
             "durationMs":30000,"fpsEstimate":29.97,
             "unsupportedNalCounts":{"STAP-B":0,"MTAP16":0,"FU-B":1,"PACI":0}}
            """.trimIndent()
        )
        assertEquals(1, result.schemaVersion)
        assertEquals("", result.error)
        assertFalse(result.cancelled)
        assertEquals("/cache/rtp/1/2/s4.h264", result.esPath)
        assertEquals("/cache/rtp/1/2/s4.vidx", result.indexPath)
        assertEquals("H264", result.codec)
        assertEquals(1280, result.width)
        assertEquals(720, result.height)
        assertEquals("High", result.profile)
        assertEquals("3.1", result.level)
        assertEquals("Z0LAHtk=", result.csd.sps)
        assertEquals("aM4BQA==", result.csd.pps)
        assertEquals(null, result.csd.vps)
        assertEquals(900L, result.frames)
        assertEquals(30L, result.keyframes)
        assertEquals(2L, result.corruptFrames)
        assertEquals(0L, result.firstKeyframeIndex)
        assertEquals(30000L, result.durationMs)
        assertEquals(29.97, result.fpsEstimate, 0.0001)
        assertEquals(1L, result.unsupportedNalCounts["FU-B"])
        assertTrue(result.isSuccess)
        assertTrue(result.hasFiles)
        assertTrue(result.widthKnown)
    }

    @Test
    fun `the pre populated neutral result parses without throwing`() {
        // 这一段就是 RtpJni.cpp 里那个 root 的初值，逐字抄下来：原生保证失败路径
        // 也是这个形状，解析器必须能从它里面读出「什么都没有」。
        val result = repository.parseVideoExportResult(
            """
            {"schemaVersion":1,"error":"","cancelled":false,"esPath":"","indexPath":"",
             "codec":"","width":0,"height":0,"profile":"","level":"",
             "csd":{"sps":null,"pps":null,"vps":null},
             "frames":0,"keyframes":0,"corruptFrames":0,"firstKeyframeIndex":-1,
             "durationMs":0,"fpsEstimate":0.0,
             "unsupportedNalCounts":{"STAP-B":0,"MTAP16":0,"FU-B":0,"PACI":0}}
            """.trimIndent()
        )
        assertEquals("", result.error)
        assertFalse(result.cancelled)
        assertFalse(result.hasFiles)
        assertTrue(result.csd.isEmpty)
        // JSONObject.NULL 不能走 optString（会得到字符串 "null"）。
        assertEquals(null, result.csd.sps)
        assertEquals(null, result.csd.pps)
        assertEquals(null, result.csd.vps)
        assertEquals(-1L, result.firstKeyframeIndex)
        // 契约里的四个键即使全是 0 也在，解析后仍然是四个键。
        assertEquals(4, result.unsupportedNalCounts.size)
        assertEquals(0L, result.unsupportedNalPackets)
        assertTrue(result.isSuccess)
        assertFalse(result.widthKnown)
    }

    @Test
    fun `unsupported nal counts keeps the types the contract does not fix`() {
        val result = repository.parseVideoExportResult(
            """{"schemaVersion":1,"error":"","esPath":"a","indexPath":"b",
                "unsupportedNalCounts":{"STAP-B":0,"MTAP16":0,"FU-B":0,"PACI":3,
                "AP(DONL)":2,"type31":7,"reserved":1}}"""
        )
        assertEquals(7, result.unsupportedNalCounts.size)
        assertEquals(3L, result.unsupportedNalCounts["PACI"])
        assertEquals(2L, result.unsupportedNalCounts["AP(DONL)"])
        assertEquals(7L, result.unsupportedNalCounts["type31"])
        assertEquals(13L, result.unsupportedNalPackets)
    }

    @Test
    fun `widthSource unknown is carried through and means the size is unknown`() {
        val result = repository.parseVideoExportResult(
            """{"schemaVersion":1,"error":"","width":0,"height":0,"widthSource":"unknown",
                "esPath":"a","indexPath":"b"}"""
        )
        assertEquals("unknown", result.widthSource)
        assertFalse(result.widthKnown)

        // 键缺失即「宽高是真的」——别把缺省读成 unknown。
        val known = repository.parseVideoExportResult(
            """{"schemaVersion":1,"error":"","width":1280,"height":720,
                "esPath":"a","indexPath":"b"}"""
        )
        assertEquals("", known.widthSource)
        assertTrue(known.widthKnown)
    }

    @Test
    fun `a native error keeps the codec and the counters that came with it`() {
        val result = repository.parseVideoExportResult(
            """{"schemaVersion":1,"error":"缺少参数集（SDP 与带内均未找到）",
                "cancelled":false,"esPath":"","indexPath":"","codec":"H265",
                "frames":0,"keyframes":0,"corruptFrames":0,"firstKeyframeIndex":-1}"""
        )
        assertEquals("缺少参数集（SDP 与带内均未找到）", result.error)
        assertEquals("H265", result.codec)
        assertFalse(result.isSuccess)
        assertFalse(result.hasFiles)
    }

    @Test
    fun `a cancelled request is not a success even with an errorless envelope`() {
        val result = repository.parseVideoExportResult(
            """{"schemaVersion":1,"error":"","cancelled":true,"esPath":"","indexPath":""}"""
        )
        assertTrue(result.cancelled)
        assertFalse(result.isSuccess)
    }

    @Test
    fun `missing fields fall back to the neutral values instead of throwing`() {
        val result = repository.parseVideoExportResult("""{"schemaVersion":1}""")
        assertEquals("", result.esPath)
        assertEquals("", result.indexPath)
        assertEquals("", result.codec)
        assertEquals(0, result.width)
        assertEquals(0, result.height)
        assertEquals(0L, result.frames)
        assertEquals(0L, result.keyframes)
        assertEquals(-1L, result.firstKeyframeIndex)
        assertEquals(0.0, result.fpsEstimate, 0.0)
        assertTrue(result.csd.isEmpty)
        assertTrue(result.unsupportedNalCounts.isEmpty())
        assertEquals("", result.widthSource)
        assertFalse(result.cancelled)
    }

    @Test
    fun `malformed json returns a malformed error without throwing`() {
        val result = repository.parseVideoExportResult("not json at all")
        assertEquals("Malformed RTP video export response.", result.error)
        assertFalse(result.isSuccess)
        assertFalse(result.hasFiles)
    }

    @Test
    fun `no open capture short circuits before any jni call`() {
        // PacketRepository() 的会话句柄是 0，所以这条路径必然走「没有会话」分支。
        val result = repository.exportVideo(
            scanGeneration = 1L,
            streamId = "s0",
            codec = "H264",
            startAtKeyframe = true,
            dropCorrupt = false,
            outDir = java.io.File("unused")
        )
        assertEquals("No capture is open.", result.error)
        assertFalse(result.isSuccess)
    }
}
