// Copyright (c) 2026 cheig
// LayerAnalyzer - https://github.com/cheig/LayerAnalyzer
// Licensed under GNU GPL version 3; see LICENSE.

package com.example.layanalyzer.model

import com.example.layanalyzer.data.PacketRepository
import com.example.layanalyzer.data.RtpRepository
import org.json.JSONObject
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Test

/**
 * [RtpCodecCatalog] 与覆盖表请求 JSON 的纯 JVM 单测（RTP1-KT-04）。
 *
 * 规范 ID / 默认时钟来自 RtpCodecCatalog.kt
 * （原生 `RtpCodecNames` 用的是同一张表）。
 *
 * 覆盖表 → JSON 的用例**不断言整串字面量**：JVM 测试用的 `org.json`
 * （`JSONObject` 内部是 `HashMap`，Android 实现也一样）不保证键顺序，
 * 因此改为把结果解析回来做结构断言（另加一条转义用例证明用的是
 * `JSONObject` 转义而不是手工拼串）。
 */
class RtpCodecCatalogTest {

    @Test
    fun `every entry id is unique`() {
        assertEquals(
            RtpCodecCatalog.entries.size,
            RtpCodecCatalog.entries.map { it.id }.toSet().size
        )
    }

    @Test
    fun `byId is case insensitive and unknown ids are null`() {
        assertEquals("g711A", RtpCodecCatalog.byId("g711a")?.id)
        assertEquals("g711A", RtpCodecCatalog.byId("G711A")?.id)
        assertEquals("opus", RtpCodecCatalog.byId("OPUS")?.id)
        assertNull(RtpCodecCatalog.byId("nope"))
    }

    @Test
    fun `entries cover the M1 families with the expected flags and clock rates`() {
        // 不要写魔数：断言 M1 要求的 10 个 id 全部存在（G.711A/U 一个族、两个 id）。
        val requiredIds = listOf(
            "g711A", "g711U", "L16", "AMR", "AMR-WB", "opus", "g722", "g729", "H264", "H265"
        )
        requiredIds.forEach { id ->
            assertNotNull("missing M1 codec id: $id", RtpCodecCatalog.byId(id))
        }

        // RTP4-KT-05 改了这条断言（本卡三条获准改动的既有断言之三）：
        //   旧：setOf("g711A", "g711U", "L16")，即 M1 的三个原生解码编码；
        //   新：本迭代所有「App 设计上支持解码」的编码。判据是静态的
        //   （`idSupported`），与「这个构建有没有链接 G.729 / iLBC」无关 ——
        //   后者只有原生的 getRtpCodecCapabilities() 答得出来，JVM 测试问不了 JNI，
        //   所以那两个编码在这里也是 true，为 false 的只剩 H264 / H265（视频）。
        val supported = RtpCodecCatalog.entries.filter { it.idSupported }.map { it.id }.toSet()
        assertEquals(
            setOf(
                "g711A", "g711U", "L16", "g722", "g729", "iLBC",
                "G726-16", "G726-24", "G726-32", "G726-40",
                "AAL2-G726-16", "AAL2-G726-24", "AAL2-G726-32", "AAL2-G726-40",
                "AMR", "AMR-WB", "opus"
            ),
            supported
        )

        val editable = RtpCodecCatalog.entries.filter { it.clockRateEditable }.map { it.id }.toSet()
        assertEquals(setOf("AMR-WB"), editable)

        assertEquals(16000, RtpCodecCatalog.byId("AMR-WB")!!.clockRate)
        assertEquals(48000, RtpCodecCatalog.byId("opus")!!.clockRate)
    }

    @Test
    fun `override list serializes to the native contract`() {
        val request = RtpRepository(PacketRepository())
            .buildOverridesRequest(listOf(RtpPayloadOverride(96, "AMR-WB", 16000, 1)))

        val root = JSONObject(request)
        // 顶层只有 overrides 一个键。
        assertEquals(1, root.length())
        val items = root.getJSONArray("overrides")
        assertEquals(1, items.length())
        val item = items.getJSONObject(0)
        assertEquals(96, item.getInt("pt"))
        assertEquals("AMR-WB", item.getString("codec"))
        assertEquals(16000, item.getInt("clockRate"))
        assertEquals(1, item.getInt("channels"))
    }

    @Test
    fun `codec names are escaped by the json encoder`() {
        val request = RtpRepository(PacketRepository())
            .buildOverridesRequest(listOf(RtpPayloadOverride(97, "a\"b", 8000, 1)))

        val item = JSONObject(request).getJSONArray("overrides").getJSONObject(0)
        assertEquals("a\"b", item.getString("codec"))
    }
}
