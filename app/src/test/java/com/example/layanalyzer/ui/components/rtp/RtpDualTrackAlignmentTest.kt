package com.example.layanalyzer.ui.components.rtp

import com.example.layanalyzer.model.RtpDtmfEvent
import com.example.layanalyzer.model.RtpEvent
import com.example.layanalyzer.model.RtpGap
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertSame
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * 双轨播放器的共享时间轴换算（RTP3-UI-03）的 JVM 测试。
 *
 * 被测函数全是纯 Kotlin（不引用 `android.*`，也不碰 Compose 运行时），所以是普通 JUnit。
 *
 * 夹具数字刻意取「桶时长整 20 ms」（`samplesPerBucket = 160`、`sampleRate = 8000`），
 * 这样偏移与桶数的对应关系一眼可验：`offsetMs / 20` 就是前置静音桶数。
 */
class RtpDualTrackAlignmentTest {

    private val framePeaks = shortArrayOf(1, 2, 3, 4)

    @Test
    fun `zero offset leaves the track untouched`() {
        val aligned = rtpAlignTrackToSharedAxis(
            peaks = framePeaks,
            samplesPerBucket = SAMPLES_PER_BUCKET,
            sampleRate = SAMPLE_RATE,
            offsetMs = 0L,
            mainSampleRate = SAMPLE_RATE
        )

        assertSame(framePeaks, aligned.peaks)
        assertEquals(0, aligned.shiftBuckets)
        assertEquals(SAMPLES_PER_BUCKET, aligned.samplesPerBucket)
    }

    @Test
    fun `offset becomes leading silence buckets of min-max pairs`() {
        val aligned = rtpAlignTrackToSharedAxis(
            peaks = framePeaks,
            samplesPerBucket = SAMPLES_PER_BUCKET,
            sampleRate = SAMPLE_RATE,
            offsetMs = 1_000L,
            mainSampleRate = SAMPLE_RATE
        )

        // 1000 ms / 20 ms = 50 个静音桶，每桶 2 个 short。
        assertEquals(50, aligned.shiftBuckets)
        assertEquals(50 * 2 + framePeaks.size, aligned.peaks.size)
        for (index in 0 until 100) {
            assertEquals("padding[$index] must be silence", 0, aligned.peaks[index].toInt())
        }
        assertArrayEquals(framePeaks, aligned.peaks.copyOfRange(100, aligned.peaks.size))
    }

    @Test
    fun `sub-bucket offset rounds to the nearest bucket`() {
        // 1050 ms / 20 ms = 52.5 个桶，四舍五入到 53；误差只有半个桶。
        val aligned = rtpAlignTrackToSharedAxis(
            peaks = framePeaks,
            samplesPerBucket = SAMPLES_PER_BUCKET,
            sampleRate = SAMPLE_RATE,
            offsetMs = 1_050L,
            mainSampleRate = SAMPLE_RATE
        )

        assertEquals(53, aligned.shiftBuckets)
    }

    @Test
    fun `bucket size is rescaled so both tracks keep the same bucket duration`() {
        // 16 kHz 的轨道按 160 采样一桶 = 10 ms；放到 8 kHz 主轨上必须换算成 80 采样一桶，
        // 否则 RtpWaveform 用主轨采样率算出来的每桶时长会翻倍，第二条轨道的时间轴就错位了。
        val aligned = rtpAlignTrackToSharedAxis(
            peaks = framePeaks,
            samplesPerBucket = 160,
            sampleRate = 16_000,
            offsetMs = 1_000L,
            mainSampleRate = SAMPLE_RATE
        )

        assertEquals(80, aligned.samplesPerBucket)
        // 换算之后仍是 10 ms 一桶：1000 ms 就是 100 个桶。
        assertEquals(100, aligned.shiftBuckets)
    }

    @Test
    fun `a missing bucket size is never guessed into a shift`() {
        // samplesPerBucket = 0 意味着不知道一桶多少毫秒；此时补零等于把轨道摆到一个错的位置。
        val aligned = rtpAlignTrackToSharedAxis(
            peaks = framePeaks,
            samplesPerBucket = 0,
            sampleRate = SAMPLE_RATE,
            offsetMs = 1_000L,
            mainSampleRate = SAMPLE_RATE
        )

        assertEquals(0, aligned.shiftBuckets)
        assertSame(framePeaks, aligned.peaks)
    }

    @Test
    fun `an empty track stays empty`() {
        val aligned = rtpAlignTrackToSharedAxis(
            peaks = ShortArray(0),
            samplesPerBucket = SAMPLES_PER_BUCKET,
            sampleRate = SAMPLE_RATE,
            offsetMs = 5_000L,
            mainSampleRate = SAMPLE_RATE
        )

        assertEquals(0, aligned.peaks.size)
        assertEquals(0, aligned.shiftBuckets)
    }

    @Test
    fun `an absurd offset is clamped to the padding cap`() {
        // 1 采样一桶 @ 1 kHz = 1 ms 一桶；偏移取 Long 的极大值，换算必须先夹住再乘 1000
        // （直接 `offsetMs * 1000` 会溢出 Long）。
        val aligned = rtpAlignTrackToSharedAxis(
            peaks = framePeaks,
            samplesPerBucket = 1,
            sampleRate = 1_000,
            offsetMs = Long.MAX_VALUE / 4,
            mainSampleRate = 1_000
        )

        assertEquals(500_000, aligned.shiftBuckets)
        assertTrue(aligned.peaks.size <= 500_000 * 2 + framePeaks.size)
    }

    @Test
    fun `track time maps onto the shared axis and back`() {
        assertEquals(1_250L, rtpSharedAxisMs(ownMs = 250L, offsetMs = 1_000L))
        assertEquals(250L, rtpTrackLocalMs(sharedMs = 1_250L, offsetMs = 1_000L))
        // 播放头落在前置静音里时，该轨自身的时间夹到 0（不是负数）。
        assertEquals(0L, rtpTrackLocalMs(sharedMs = 400L, offsetMs = 1_000L))
        assertEquals(0L, rtpSharedAxisMs(ownMs = -50L, offsetMs = 0L))
    }

    @Test
    fun `gaps and events move by the same offset`() {
        val gaps = listOf(RtpGap(atMs = 300L, durMs = 200L, reason = "lost", clipped = false, frame = 7L))
        val events = listOf(RtpEvent(atMs = 100L, type = "dtmf", value = "5", frame = 9L))

        val shiftedGaps = rtpShiftGaps(gaps, offsetMs = 1_000L)
        assertEquals(1_300L, shiftedGaps.single().atMs)
        // 时长属于 gap 自身，不跟着平移。
        assertEquals(200L, shiftedGaps.single().durMs)

        val shiftedEvents = rtpShiftEvents(events, offsetMs = 1_000L)
        assertEquals(1_100L, shiftedEvents.single().atMs)
        assertEquals("5", shiftedEvents.single().value)

        // 偏移为 0 时不分配新列表。
        assertSame(gaps, rtpShiftGaps(gaps, offsetMs = 0L))
        assertSame(events, rtpShiftEvents(events, offsetMs = 0L))
    }

    @Test
    fun `dtmf events become labeled markers on the shared axis`() {
        val dtmf = listOf(
            RtpDtmfEvent(digit = "7", atMs = 2_400L, durMs = 120L, volume = 10, frame = 512L)
        )

        val markers = rtpDtmfEvents(dtmf, offsetMs = 1_000L)

        assertEquals(1, markers.size)
        assertEquals(3_400L, markers.single().atMs)
        assertEquals("dtmf", markers.single().type)
        assertEquals("7", markers.single().value)
        assertEquals(512L, markers.single().frame)
    }

    private companion object {
        const val SAMPLE_RATE = 8_000
        const val SAMPLES_PER_BUCKET = 160
    }
}
