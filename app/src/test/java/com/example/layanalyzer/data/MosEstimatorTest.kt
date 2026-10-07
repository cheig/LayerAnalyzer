package com.example.layanalyzer.data

import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotEquals
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

class MosEstimatorTest {

    private fun estimateOrFail(
        codec: String,
        lossPercent: Double,
        oneWayDelayMs: Double
    ): MosEstimate =
        MosEstimator.estimate(codec, lossPercent, oneWayDelayMs)
            ?: throw AssertionError("expected a MOS estimate for $codec")

    @Test
    fun `g711A without loss at 100 ms one way delay scores about 4_36`() {
        val result = estimateOrFail("g711A", 0.0, 100.0)

        // Ie_eff = 0, Id = 2.4, R = 90.8 -> MOS = 4.3581...
        assertEquals(4.358, result.mos, 0.001)
        assertTrue(result.mos in 4.35..4.45)
        assertEquals(90.8, result.r, 1e-9)
        assertEquals(0.0, result.ieEff, 0.0)
    }

    @Test
    fun `g711U uses the same impairment row as g711A`() {
        val aLaw = estimateOrFail("g711A", 0.0, 100.0)
        val uLaw = estimateOrFail("g711U", 0.0, 100.0)

        assertTrue(uLaw.mos in 4.35..4.45)
        assertEquals(aLaw.mos, uLaw.mos, 0.0)
        assertEquals(aLaw.r, uLaw.r, 0.0)
        assertEquals(aLaw.ieEff, uLaw.ieEff, 0.0)
    }

    @Test
    fun `mos decreases strictly as loss grows`() {
        val at0 = estimateOrFail("g711U", 0.0, 100.0)
        val at2 = estimateOrFail("g711U", 2.0, 100.0)
        val at5 = estimateOrFail("g711U", 5.0, 100.0)
        val at10 = estimateOrFail("g711U", 10.0, 100.0)

        assertTrue(at0.mos > at2.mos && at2.mos > at5.mos && at5.mos > at10.mos)
        assertTrue(at0.r > at2.r && at2.r > at5.r && at5.r > at10.r)
        assertEquals(0.0, at0.ieEff, 0.0)
        assertEquals(95.0 * 2.0 / (2.0 + 25.1), at2.ieEff, 1e-9)
        assertEquals(95.0 * 5.0 / (5.0 + 25.1), at5.ieEff, 1e-9)
        assertEquals(95.0 * 10.0 / (10.0 + 25.1), at10.ieEff, 1e-9)
    }

    @Test
    fun `codecs without a narrowband Ie value return null`() {
        assertNull(MosEstimator.estimate("g722", 0.0, 100.0))
        assertNull(MosEstimator.estimate("AMR-WB", 0.0, 100.0))
        assertNull(MosEstimator.estimate("opus", 0.0, 100.0))
        // 未知、空串和事件流同样不猜：没有窄带表项就不给估算。
        assertNull(MosEstimator.estimate("g711", 0.0, 100.0))
        assertNull(MosEstimator.estimate("telephone-event", 0.0, 100.0))
        assertNull(MosEstimator.estimate("", 0.0, 100.0))
        assertNull(MosEstimator.estimate("   ", 0.0, 100.0))
    }

    @Test
    fun `saturated loss and huge delay clamp R to zero and mos to one`() {
        val result = estimateOrFail("g711U", 100.0, 2000.0)

        // Ie_eff = 75.939..., Id = 248.497 -> raw R = -231.23...
        assertEquals(0.0, result.r, 0.0)
        assertEquals(1.0, result.mos, 0.0)
    }

    @Test
    fun `inputs carry the four documented keys and the estimate flag stays true`() {
        val result = estimateOrFail("g711A", 5.0, 100.0)

        assertTrue(result.isEstimate)
        assertEquals(
            setOf("codec", "lossPercent", "oneWayDelayMs", "delaySource"),
            result.inputs.keys
        )
        assertEquals("g711A", result.inputs["codec"])
        assertEquals("5.0", result.inputs["lossPercent"])
        assertEquals("100.0", result.inputs["oneWayDelayMs"])
        assertEquals(MosEstimator.DEFAULT_DELAY_SOURCE, result.inputs["delaySource"])
        assertEquals("default", result.inputs["delaySource"])
    }

    @Test
    fun `delay source is recorded when the caller supplies one`() {
        val result = MosEstimator.estimate("g711U", 1.0, 62.5, delaySource = "rtcp")
            ?: throw AssertionError("expected a MOS estimate for g711U")

        assertEquals("rtcp", result.inputs["delaySource"])
        assertEquals(62.5, result.oneWayDelayMs, 0.0)
    }

    @Test
    fun `loss and delay are reported back unchanged`() {
        val result = estimateOrFail("g711A", 5.0, 120.0)

        assertEquals(5.0, result.lossPercent, 0.0)
        assertEquals(120.0, result.oneWayDelayMs, 0.0)
        assertEquals("120.0", result.inputs["oneWayDelayMs"])
    }

    @Test
    fun `lookup ignores case and surrounding whitespace`() {
        val canonical = estimateOrFail("g711A", 4.0, 100.0)
        val upper = estimateOrFail("G711A", 4.0, 100.0)
        val lower = estimateOrFail("g711a", 4.0, 100.0)
        val padded = estimateOrFail("  g711A ", 4.0, 100.0)

        assertEquals(canonical.ieEff, upper.ieEff, 0.0)
        assertEquals(canonical.ieEff, lower.ieEff, 0.0)
        assertEquals(canonical.ieEff, padded.ieEff, 0.0)
        assertEquals(canonical.mos, upper.mos, 0.0)
        // 回填的 codec 是调用方原样传入的字符串，不做规范化。
        assertEquals("G711A", upper.codec)
        assertEquals("g711a", lower.codec)
    }

    @Test
    fun `default one way delay is 100 ms`() {
        assertEquals(100.0, MosEstimator.defaultOneWayDelayMs(), 0.0)
    }

    @Test
    fun `g729 uses the G729A with VAD row`() {
        val result = estimateOrFail("g729", 0.0, 100.0)

        // Ie = 11, Bpl = 19; Id = 2.4 -> R = 79.8
        assertEquals(11.0, result.ieEff, 1e-9)
        assertEquals(79.8, result.r, 1e-9)
    }

    @Test
    fun `the delay knee above 177_3 ms adds the non linear term`() {
        val belowKnee = estimateOrFail("g711A", 0.0, 177.3)
        val aboveKnee = estimateOrFail("g711A", 0.0, 300.0)

        assertEquals(93.2 - 0.024 * 177.3, belowKnee.r, 1e-9)
        // 0.024 * 300 + 0.11 * (300 - 177.3) = 7.2 + 13.497
        assertEquals(93.2 - 20.697, aboveKnee.r, 1e-6)
        assertTrue(aboveKnee.r < belowKnee.r)
        assertNotEquals(
            93.2 - 0.024 * 300.0,
            aboveKnee.r,
            1e-6
        )
    }

    @Test
    fun `loss above 100 percent is clamped for the computation but echoed as given`() {
        val clamped = estimateOrFail("g711U", 100.0, 100.0)
        val overRange = estimateOrFail("g711U", 150.0, 100.0)

        assertEquals(95.0 * 100.0 / (100.0 + 25.1), clamped.ieEff, 1e-9)
        assertEquals(clamped.ieEff, overRange.ieEff, 0.0)
        assertEquals(clamped.r, overRange.r, 0.0)
        assertEquals(150.0, overRange.lossPercent, 0.0)
    }
}
