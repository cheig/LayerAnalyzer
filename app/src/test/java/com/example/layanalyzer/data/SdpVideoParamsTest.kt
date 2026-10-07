package com.example.layanalyzer.data

import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test
import java.util.Base64

/**
 * RTP5-KT-00 的 SDP 参数集提取单测（纯 JVM）。
 *
 * **为什么每条用例都走 `SdpVideoParams.parse` 而不是 `from`。** 卡片冻结的 `from(...)`
 * 内部用 `android.util.Base64` 解码，而本模块没有 Robolectric、也没有
 * `isReturnDefaultValues`，JVM 上碰 `android.*` 会抛「not mocked」。所以凡是**会解码
 * Base64** 的用例都注入 `java.util.Base64`（[jvmBase64Decode]）—— 这正是那个解码参数
 * 存在的理由，不是绕过测试。`from(...)` 只在一个不碰 Base64 的用例里被直接断言
 * （`from delegates to the same rules for an fmtp without parameter sets`），证明公开
 * 签名确实是 [SdpVideoParams.parse] 的转发。
 *
 * **断言的是字节内容，不是长度。** 每个 Base64 字面量都是手工核对过的、长度 4 的倍数：
 *
 *  - `AQIDBA==` → 01 02 03 04（SPS）
 *  - `BQYHCA==` → 05 06 07 08（PPS）
 *  - `CQoLDA==` → 09 0A 0B 0C（VPS）
 *  - `DQ4PEA==` → 0D 0E 0F 10（多余的参数集）
 *
 * 它们同时覆盖了另一件事：值里带 Base64 填充 `=`，而键值分隔符必须取**第一个** `=`，
 * 取最后一个会把 SPS 切坏。
 */
class SdpVideoParamsTest {

    /** 注入给 [SdpVideoParams.parse] 的解码器：非法输入抛 `IllegalArgumentException`，与生产一致。 */
    private fun jvmBase64Decode(value: String): ByteArray? = Base64.getDecoder().decode(value)

    /** 全部用例的统一入口；PT 默认 96，个别用例自己指定。 */
    private fun parse(
        encodingName: String,
        fmtp: String?,
        payloadType: Int = 96
    ): SdpVideoParams.ParseResult =
        SdpVideoParams.parse(payloadType, encodingName, fmtp, ::jvmBase64Decode)

    private val spsBytes = byteArrayOf(0x01, 0x02, 0x03, 0x04)
    private val ppsBytes = byteArrayOf(0x05, 0x06, 0x07, 0x08)
    private val vpsBytes = byteArrayOf(0x09, 0x0A, 0x0B, 0x0C)
    private val extraBytes = byteArrayOf(0x0D, 0x0E, 0x0F, 0x10)

    @Test
    fun `H264 the first parameter set is the SPS and the second is the PPS`() {
        val result = parse(
            "H264",
            "profile-level-id=42e01f;packetization-mode=1;sprop-parameter-sets=AQIDBA==,BQYHCA=="
        )

        assertEquals(1, result.sets.sps.size)
        assertArrayEquals(spsBytes, result.sets.sps.single())
        assertEquals(1, result.sets.pps.size)
        assertArrayEquals(ppsBytes, result.sets.pps.single())
        // H.264 没有 VPS 这一说。
        assertTrue(result.sets.vps.isEmpty())
        assertEquals(1, result.sets.packetizationMode)
        assertEquals("42e01f", result.sets.profileLevelId)
        assertNull(result.sets.donDiff)
        assertTrue(result.hasParameterSets)
        // 只有两项参数集，没有多余的、也没有解不出来的。
        assertEquals(0, result.extraParameterSetCount)
        assertEquals(0, result.undecodableCount)
    }

    @Test
    fun `H264 parameter sets beyond the first two are dropped and only counted`() {
        val result = parse(
            "H264",
            "sprop-parameter-sets=AQIDBA==,BQYHCA==,CQoLDA==,DQ4PEA==,AQIDBA=="
        )

        // 只保留第一个 SPS 与第一个 PPS：后面的一个字节都不该进结果。
        assertEquals(1, result.sets.sps.size)
        assertArrayEquals(spsBytes, result.sets.sps.single())
        assertEquals(1, result.sets.pps.size)
        assertArrayEquals(ppsBytes, result.sets.pps.single())
        // 第 3、4、5 项（下标 2、3、4）按 SPS/PPS/SPS 分类计数 —— 卡片要求进日志的那三个数。
        assertEquals(2, result.extraSpsCount)
        assertEquals(1, result.extraPpsCount)
        assertEquals(3, result.extraParameterSetCount)
        assertEquals(0, result.undecodableCount)
    }

    @Test
    fun `H265 reads the three separate keys into VPS SPS and PPS`() {
        val result = parse(
            "H265",
            "sprop-vps=CQoLDA==;sprop-sps=AQIDBA==;sprop-pps=BQYHCA=="
        )

        assertArrayEquals(vpsBytes, result.sets.vps.single())
        assertArrayEquals(spsBytes, result.sets.sps.single())
        assertArrayEquals(ppsBytes, result.sets.pps.single())
        assertTrue(result.hasParameterSets)
    }

    @Test
    fun `H265 ignores the H264 key rather than reading it as an SPS list`() {
        // 编码名说 H.265，却只给了 H.264 的键：不认识的键一律不看，结果全空（fail-closed）。
        val result = parse("H265", "sprop-parameter-sets=AQIDBA==,BQYHCA==")

        assertTrue(result.sets.sps.isEmpty())
        assertTrue(result.sets.pps.isEmpty())
        assertTrue(result.sets.vps.isEmpty())
        assertFalse(result.hasParameterSets)
    }

    @Test
    fun `H265 counts a key that exists but cannot be decoded`() {
        val result = parse("H265", "sprop-sps=AQIDBA==;sprop-pps=not*base64")

        assertArrayEquals(spsBytes, result.sets.sps.single())
        assertTrue(result.sets.pps.isEmpty())
        assertEquals(1, result.undecodableCount)
        assertTrue(result.hasParameterSets)
    }

    @Test
    fun `an invalid Base64 parameter set leaves that list empty and never throws`() {
        // 卡片：Base64 解码失败 → 该项为空，不要抛异常（调用方随后报「缺少参数集」）。
        // 用 H.264 的两项配合：第一项坏、第二项好，证明坏的那一项没有连累另一项。
        val result = parse("H264", "sprop-parameter-sets=not*base64,BQYHCA==")

        assertTrue(result.sets.sps.isEmpty())
        assertArrayEquals(ppsBytes, result.sets.pps.single())
        assertEquals(1, result.undecodableCount)
    }

    @Test
    fun `a decoder that returns null is treated as a failed item not a crash`() {
        // 接缝的另一种实现风格：失败回 null 而不是抛异常。两者必须等价。
        val result = SdpVideoParams.parse(96, "H264", "sprop-parameter-sets=AQIDBA==") { null }

        assertTrue(result.sets.sps.isEmpty())
        assertFalse(result.hasParameterSets)
        assertEquals(1, result.undecodableCount)
    }

    @Test
    fun `a null fmtp yields an empty result`() {
        val result = parse("H264", null)

        assertEmpty(result)
    }

    @Test
    fun `an empty or separator-only fmtp yields an empty result`() {
        // SDP 里 `a=fmtp:96 ` 后面什么都没有是合法的，直接回空而不是拿空串去解码。
        for (fmtp in listOf("", "   ", ";", ";;;", " ; ; ")) {
            assertEmpty(parse("H264", fmtp))
            assertEmpty(parse("H265", fmtp))
        }
    }

    @Test
    fun `a parameter set key with an empty value is not a zero byte parameter set`() {
        // 空串用 java.util.Base64 能「成功」解出 0 字节；0 字节的 SPS 是假数据，
        // 必须当成「没有」，否则调用方会拿它去算分辨率。
        val result = parse("H264", "sprop-parameter-sets=;packetization-mode=1")

        assertTrue(result.sets.sps.isEmpty())
        assertTrue(result.sets.pps.isEmpty())
        assertFalse(result.hasParameterSets)
    }

    @Test
    fun `packetization-mode is taken as is`() {
        assertEquals(1, parse("H264", "packetization-mode=1").sets.packetizationMode)
        assertEquals(0, parse("H264", "packetization-mode=0").sets.packetizationMode)
        // 缺失 → null；不是数字 → 也是 null（不猜一个默认值）。
        assertNull(parse("H264", null).sets.packetizationMode)
        assertNull(parse("H264", "packetization-mode=abc").sets.packetizationMode)
    }

    @Test
    fun `sprop-max-don-diff becomes donDiff`() {
        assertEquals(3, parse("H264", "sprop-max-don-diff=3").sets.donDiff)
        assertEquals(0, parse("H265", "sprop-max-don-diff=0").sets.donDiff)
        assertNull(parse("H264", "sprop-max-don-diff=x").sets.donDiff)
        assertNull(parse("H264", "packetization-mode=1").sets.donDiff)
    }

    @Test
    fun `an unknown encoding name yields an empty result`() {
        // 表外的编码名没有规则可用，一律全空（fail-closed）——包括那三个标量。
        val result = parse(
            "VP8",
            "sprop-parameter-sets=AQIDBA==;packetization-mode=1;profile-level-id=42e01f"
        )

        assertEmpty(result)
    }

    @Test
    fun `encodingName PS yields everything empty even with a fully populated fmtp`() {
        // PS（GB28181）的负载是 PS 复用流，SDP 里的这些键对它没有意义，卡片要求全空。
        val result = parse(
            "PS",
            "sprop-parameter-sets=AQIDBA==;sprop-vps=CQoLDA==;packetization-mode=1;" +
                "profile-level-id=42e01f;sprop-max-don-diff=3"
        )

        assertEmpty(result)
        assertNull(result.sets.packetizationMode)
        assertNull(result.sets.profileLevelId)
        assertNull(result.sets.donDiff)
    }

    @Test
    fun `encoding names are matched case insensitively and accept the README aliases`() {
        val fmtp = "sprop-parameter-sets=AQIDBA==,BQYHCA=="
        for (name in listOf("H264", "h264", "H264 ")) {
            assertArrayEquals(spsBytes, parse(name, fmtp).sets.sps.single())
        }
        // README §4.3 的别名表：H265 也接受 HEVC（两种大小写）。
        val h265 = "sprop-vps=CQoLDA=="
        for (name in listOf("H265", "h265", "HEVC", "hevc")) {
            assertArrayEquals(vpsBytes, parse(name, h265).sets.vps.single())
        }
        // PS 也接受 MP2P；这里只断言「走的是 PS 分支」，即全空。
        assertEmpty(parse("mp2p", fmtp))
        assertEmpty(parse("MP2P", fmtp))
    }

    @Test
    fun `keys in an unusual order with whitespace around the separators are tolerated`() {
        // 顺序打乱 + `;` 与 `=` 两边都有空白 + 逗号两边也有空白：SDP 里三种写法都出现过。
        val result = parse(
            "H264",
            "  sprop-parameter-sets = AQIDBA== ,  BQYHCA== ; packetization-mode= 1 ;" +
                " profile-level-id = 42e01f ; sprop-max-don-diff = 2 "
        )

        assertArrayEquals(spsBytes, result.sets.sps.single())
        assertArrayEquals(ppsBytes, result.sets.pps.single())
        assertEquals(1, result.sets.packetizationMode)
        assertEquals("42e01f", result.sets.profileLevelId)
        assertEquals(2, result.sets.donDiff)
    }

    @Test
    fun `a repeated key keeps the first occurrence`() {
        // SDP 不允许同一个参数出现两次；真出现时取第一个，行为可预期而不是取最后一个。
        val result = parse("H264", "packetization-mode=1;packetization-mode=0")

        assertEquals(1, result.sets.packetizationMode)
    }

    @Test
    fun `the payload type comes back on the parse result`() {
        // payloadType 不参与任何规则，但它没有被丢掉：结果里带着它，调用方打日志时不必再抄。
        val result = parse("H264", "sprop-parameter-sets=AQIDBA==", payloadType = 112)

        assertEquals(112, result.payloadType)
        assertArrayEquals(spsBytes, result.sets.sps.single())
    }

    @Test
    fun `from delegates to the same rules for an fmtp without parameter sets`() {
        // 这条是唯一直接调 `from` 的用例：它不需要解码 Base64，所以 JVM 上不会碰到
        // `android.util.Base64`（碰了就是「not mocked」）。它证明公开签名确实转发到
        // `parse`，而且返回的是 `sets` 那一半、不是整个结果。
        val sets = SdpVideoParams.from(
            96,
            "H264",
            "profile-level-id=42e01f;packetization-mode=1"
        )

        assertEquals(1, sets.packetizationMode)
        assertEquals("42e01f", sets.profileLevelId)
        assertNull(sets.donDiff)
        assertTrue(sets.sps.isEmpty())
        assertTrue(sets.pps.isEmpty())
        assertTrue(sets.vps.isEmpty())
    }

    /** 卡片意义上的「缺少参数集」：三张表全空、三个标量全 null。 */
    private fun assertEmpty(result: SdpVideoParams.ParseResult) {
        assertTrue("sps should be empty", result.sets.sps.isEmpty())
        assertTrue("pps should be empty", result.sets.pps.isEmpty())
        assertTrue("vps should be empty", result.sets.vps.isEmpty())
        assertNull(result.sets.packetizationMode)
        assertNull(result.sets.profileLevelId)
        assertNull(result.sets.donDiff)
        assertFalse(result.hasParameterSets)
        assertEquals(0, result.extraParameterSetCount)
        assertEquals(0, result.undecodableCount)
    }
}
