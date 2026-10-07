package com.example.layanalyzer.ui.components.rtp

import org.junit.Assert.assertArrayEquals
import org.junit.Test

class WaveformDownsamplingTest {

    @Test
    fun `keeps peaks unchanged when no downsampling is needed`() {
        val peaks = shortArrayOf(-5, 7, -2, 4)

        val result = downsamplePeaks(peaks, targetBuckets = 2)

        assertArrayEquals(shortArrayOf(-5, 7, -2, 4), result)
    }

    @Test
    fun `merges each pair of buckets at two to one`() {
        val peaks = shortArrayOf(-10, 20, -30, 40, 5, 6, -7, 8)

        val result = downsamplePeaks(peaks, targetBuckets = 2)

        assertArrayEquals(shortArrayOf(-30, 40, -7, 8), result)
    }

    @Test
    fun `merges a non divisible number of input buckets`() {
        val peaks = shortArrayOf(
            -1, 8,
            -9, 4,
            -3, 7,
            -4, 6,
            -2, 5
        )

        val result = downsamplePeaks(peaks, targetBuckets = 2)

        assertArrayEquals(shortArrayOf(-9, 8, -4, 6), result)
    }

    @Test
    fun `returns empty output for empty input`() {
        val result = downsamplePeaks(ShortArray(0), targetBuckets = 4)

        assertArrayEquals(ShortArray(0), result)
    }

    @Test
    fun `returns empty output for zero target buckets`() {
        val result = downsamplePeaks(shortArrayOf(-1, 1, -2, 2), targetBuckets = 0)

        assertArrayEquals(ShortArray(0), result)
    }
}
