// Copyright (c) 2026 cheig
// LayerAnalyzer - https://github.com/cheig/LayerAnalyzer
// Licensed under GNU GPL version 3; see LICENSE.

package com.example.layanalyzer.ui.components.rtp

import com.example.layanalyzer.media.VidxEntry
import com.example.layanalyzer.media.VidxFile
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * RTP5-KT-03：预览时间轴的纯逻辑（二分查找、反向查找、损坏区间）。
 *
 * 这一段是本卡**在这台机器上唯一能真跑**的部分：没有设备、没有 Robolectric，进度条上的
 * 手势与 `TextureView` 的生命周期都验不了（那是 RTP5-QA-03 的事），但「第 0 微秒是第几包」
 * 「第 1000 微秒落在那一条上」「哪几段标红」是全确定的算术，这里把它钉到下标与微秒。
 *
 * 所有边界都按 `RtpVideoPreviewTimeline.kt` 里写下的口径断言 —— 边界不是「顺手写的保护」，
 * 是那段 KDoc 承诺的行为，测试就是那段承诺本身。
 */
class RtpVideoPreviewTimelineTest {

    // ------------------------------------------------------------ 正向：位置 → 访问单元

    @Test
    fun `an empty index has no access unit at any position`() {
        assertNull(rtpPreviewAccessUnitAt(0L, emptyList()))
        assertNull(rtpPreviewAccessUnitAt(1_000_000L, emptyList()))
    }

    @Test
    fun `a single access unit covers everything from its pts on`() {
        val entries = listOf(entry(ptsUs = 0L, frame = 12))

        // 第一个 PTS 之前没有任何一帧：不是「夹到第 0 条」。
        assertNull(rtpPreviewAccessUnitAt(-1L, entries))
        assertEquals(0, rtpPreviewAccessUnitAt(0L, entries)?.index)
        assertEquals(0, rtpPreviewAccessUnitAt(1L, entries)?.index)
        assertEquals(0, rtpPreviewAccessUnitAt(999_999L, entries)?.index)
    }

    @Test
    fun `a single access unit whose pts is not zero has nothing before it`() {
        val entries = listOf(entry(ptsUs = 100L, frame = 12))

        assertNull(rtpPreviewAccessUnitAt(99L, entries))
        assertEquals(0, rtpPreviewAccessUnitAt(100L, entries)?.index)
        assertEquals(0, rtpPreviewAccessUnitAt(101L, entries)?.index)
    }

    @Test
    fun `the bisection lands on the access unit that starts at the position`() {
        val entries = listOf(
            entry(ptsUs = 0L, frame = 12),
            entry(ptsUs = 1_000L, frame = 13),
            entry(ptsUs = 2_000L, frame = 15)
        )

        assertEquals(0, rtpPreviewAccessUnitAt(0L, entries)?.index)
        // 一条记录覆盖到**下一条**开始之前，所以 999 仍然是第 0 条。
        assertEquals(0, rtpPreviewAccessUnitAt(999L, entries)?.index)
        // 正好落在 PTS 上就是那一条自己（`<=`），不是前一条。
        assertEquals(1, rtpPreviewAccessUnitAt(1_000L, entries)?.index)
        assertEquals(1, rtpPreviewAccessUnitAt(1_001L, entries)?.index)
        assertEquals(1, rtpPreviewAccessUnitAt(1_999L, entries)?.index)
        assertEquals(2, rtpPreviewAccessUnitAt(2_000L, entries)?.index)
    }

    @Test
    fun `a position after the last access unit is still the last access unit`() {
        val entries = listOf(
            entry(ptsUs = 0L, frame = 12),
            entry(ptsUs = 1_000L, frame = 13)
        )

        assertEquals(1, rtpPreviewAccessUnitAt(1_001L, entries)?.index)
        assertEquals(1, rtpPreviewAccessUnitAt(999_999_999L, entries)?.index)
        assertEquals(1, rtpPreviewAccessUnitAt(Long.MAX_VALUE, entries)?.index)
    }

    @Test
    fun `the packet number comes off the entry the bisection found`() {
        val entries = listOf(
            entry(ptsUs = 0L, frame = 12),
            entry(ptsUs = 1_000L, frame = 40)
        )

        assertEquals(12, rtpPreviewAccessUnitAt(500L, entries)?.entry?.firstFrame)
        assertEquals(40, rtpPreviewAccessUnitAt(1_000L, entries)?.entry?.firstFrame)
    }

    @Test
    fun `equal presentation times land on the last of them`() {
        // 同一微秒的两条记录：upper_bound 减一落在后一条上。这不是「随便挑一个」——
        // 它钉住的是 bisection 的定义，换成别的实现（例如 lower_bound）就会换一条。
        val entries = listOf(
            entry(ptsUs = 0L, frame = 12),
            entry(ptsUs = 0L, frame = 13),
            entry(ptsUs = 1_000L, frame = 15)
        )

        assertEquals(1, rtpPreviewAccessUnitAt(0L, entries)?.index)
        assertEquals(13, rtpPreviewAccessUnitAt(0L, entries)?.entry?.firstFrame)
    }

    @Test
    fun `a non monotonic index is not repaired and its landings are pinned`() {
        // KT-01 的封装器会把逆序的 PTS 推成 +1 微秒，但**索引本身**仍然可能带着逆序值
        // （人工构造的、或被别处改过的 `.vidx`）。本函数照实返回二分的落点，不排序、
        // 不回退，所以下面这几个下标是「决定」，不是巧合。
        val entries = listOf(
            entry(ptsUs = 0L, frame = 12),
            entry(ptsUs = 100L, frame = 13),
            entry(ptsUs = 50L, frame = 14),
            entry(ptsUs = 300L, frame = 15)
        )

        // 二分先看下标 2（50 <= 60），再看下标 3（300 > 60），落在下标 2。
        assertEquals(2, rtpPreviewAccessUnitAt(60L, entries)?.index)
        // 下标 1 的 PTS（100）虽然 <= 120，二分看不到它：它落在下标 2（PTS 50）上。
        assertEquals(2, rtpPreviewAccessUnitAt(120L, entries)?.index)
        assertEquals(14, rtpPreviewAccessUnitAt(120L, entries)?.entry?.firstFrame)
        // 大于所有 PTS 时落在最后一条。
        assertEquals(3, rtpPreviewAccessUnitAt(400L, entries)?.index)
        assertEquals(0, rtpPreviewAccessUnitAt(0L, entries)?.index)
    }

    // ------------------------------------------------------------ 反向：数据包号 → 位置

    @Test
    fun `the inverse lookup has nothing before the first access unit`() {
        val entries = listOf(
            entry(ptsUs = 0L, frame = 10),
            entry(ptsUs = 1_000L, frame = 20)
        )

        assertNull(rtpPreviewSeekUsForFrame(9L, entries))
        assertNull(rtpPreviewSeekUsForFrame(-1L, entries))
        assertEquals(0L, rtpPreviewSeekUsForFrame(10L, entries))
    }

    @Test
    fun `the inverse lookup returns the access unit that owns the packet`() {
        val entries = listOf(
            entry(ptsUs = 0L, frame = 10),
            entry(ptsUs = 1_000L, frame = 20),
            entry(ptsUs = 2_000L, frame = 30)
        )

        // 一个 AU 覆盖 [firstFrame, 下一个 AU 的 firstFrame)。
        assertEquals(0L, rtpPreviewSeekUsForFrame(10L, entries))
        assertEquals(0L, rtpPreviewSeekUsForFrame(15L, entries))
        assertEquals(0L, rtpPreviewSeekUsForFrame(19L, entries))
        assertEquals(1_000L, rtpPreviewSeekUsForFrame(20L, entries))
        assertEquals(1_000L, rtpPreviewSeekUsForFrame(29L, entries))
        assertEquals(2_000L, rtpPreviewSeekUsForFrame(30L, entries))
    }

    @Test
    fun `the inverse lookup clamps a packet beyond the last access unit`() {
        val entries = listOf(
            entry(ptsUs = 0L, frame = 10),
            entry(ptsUs = 1_000L, frame = 20)
        )

        // 最后一个 AU 之后的包（含尾部丢包造成的空洞）跳到最后一条。
        assertEquals(1_000L, rtpPreviewSeekUsForFrame(21L, entries))
        assertEquals(1_000L, rtpPreviewSeekUsForFrame(999_999L, entries))
        assertEquals(1_000L, rtpPreviewSeekUsForFrame(Long.MAX_VALUE, entries))
    }

    @Test
    fun `the inverse lookup of an empty or single entry index`() {
        assertNull(rtpPreviewSeekUsForFrame(0L, emptyList()))

        val entries = listOf(entry(ptsUs = 500L, frame = 10))
        assertNull(rtpPreviewSeekUsForFrame(9L, entries))
        assertEquals(500L, rtpPreviewSeekUsForFrame(10L, entries))
        assertEquals(500L, rtpPreviewSeekUsForFrame(10_000L, entries))
    }

    // ------------------------------------------------------------ 损坏区间

    @Test
    fun `spans are empty when there is nothing to divide by`() {
        val corrupt = listOf(entry(ptsUs = 0L, frame = 12, corrupt = true))

        // 零时长、负时长与空列表都返回空表：分母是 0 时「哪一段是红的」没有意义。
        assertTrue(rtpPreviewCorruptSpans(emptyList(), 1_000L).isEmpty())
        assertTrue(rtpPreviewCorruptSpans(corrupt, 0L).isEmpty())
        assertTrue(rtpPreviewCorruptSpans(corrupt, -1L).isEmpty())
    }

    @Test
    fun `no corrupt access unit means no span`() {
        val entries = listOf(
            entry(ptsUs = 0L, frame = 12),
            entry(ptsUs = 1_000L, frame = 13)
        )

        assertTrue(rtpPreviewCorruptSpans(entries, 2_000L).isEmpty())
    }

    @Test
    fun `every corrupt access unit merges into one full span`() {
        val entries = listOf(
            entry(ptsUs = 0L, frame = 12, corrupt = true),
            entry(ptsUs = 1_000L, frame = 13, corrupt = true),
            entry(ptsUs = 2_000L, frame = 15, corrupt = true)
        )

        val spans = rtpPreviewCorruptSpans(entries, 3_000L)
        assertEquals(1, spans.size)
        assertEquals(0f, spans.single().startFraction, DELTA)
        assertEquals(1f, spans.single().endFraction, DELTA)
    }

    @Test
    fun `a corrupt first access unit spans its own frame only`() {
        val entries = listOf(
            entry(ptsUs = 0L, frame = 12, corrupt = true),
            entry(ptsUs = 1_000L, frame = 13),
            entry(ptsUs = 2_000L, frame = 15)
        )

        val spans = rtpPreviewCorruptSpans(entries, 3_000L)
        assertEquals(1, spans.size)
        assertEquals(0f, spans.single().startFraction, DELTA)
        assertEquals(1f / 3f, spans.single().endFraction, DELTA)
    }

    @Test
    fun `a corrupt last access unit spans up to the end of the timeline`() {
        val entries = listOf(
            entry(ptsUs = 0L, frame = 12),
            entry(ptsUs = 1_000L, frame = 13, corrupt = true)
        )

        // 最后一段画到时长为止：封装器会在最后一个样本自己的时长上补齐，所以这一段不是零宽。
        val spans = rtpPreviewCorruptSpans(entries, 2_000L)
        assertEquals(1, spans.size)
        assertEquals(0.5f, spans.single().startFraction, DELTA)
        assertEquals(1f, spans.single().endFraction, DELTA)
    }

    @Test
    fun `adjacent corrupt access units merge into one span`() {
        val entries = listOf(
            entry(ptsUs = 0L, frame = 12),
            entry(ptsUs = 1_000L, frame = 13, corrupt = true),
            entry(ptsUs = 2_000L, frame = 15, corrupt = true),
            entry(ptsUs = 3_000L, frame = 16)
        )

        val spans = rtpPreviewCorruptSpans(entries, 4_000L)
        assertEquals(1, spans.size)
        assertEquals(0.25f, spans.single().startFraction, DELTA)
        assertEquals(0.75f, spans.single().endFraction, DELTA)
    }

    @Test
    fun `separated corrupt access units stay two spans`() {
        val entries = listOf(
            entry(ptsUs = 0L, frame = 12, corrupt = true),
            entry(ptsUs = 1_000L, frame = 13),
            entry(ptsUs = 2_000L, frame = 15, corrupt = true),
            entry(ptsUs = 3_000L, frame = 16)
        )

        val spans = rtpPreviewCorruptSpans(entries, 4_000L)
        assertEquals(2, spans.size)
        assertEquals(0f, spans[0].startFraction, DELTA)
        assertEquals(0.25f, spans[0].endFraction, DELTA)
        assertEquals(0.5f, spans[1].startFraction, DELTA)
        assertEquals(0.75f, spans[1].endFraction, DELTA)
    }

    @Test
    fun `three runs stay three spans`() {
        val entries = listOf(
            entry(ptsUs = 0L, frame = 1, corrupt = true),
            entry(ptsUs = 1_000L, frame = 2),
            entry(ptsUs = 2_000L, frame = 3, corrupt = true),
            entry(ptsUs = 3_000L, frame = 4),
            entry(ptsUs = 4_000L, frame = 5, corrupt = true)
        )

        val spans = rtpPreviewCorruptSpans(entries, 5_000L)
        assertEquals(3, spans.size)
        assertEquals(0f, spans[0].startFraction, DELTA)
        assertEquals(0.2f, spans[0].endFraction, DELTA)
        assertEquals(0.4f, spans[1].startFraction, DELTA)
        assertEquals(0.6f, spans[1].endFraction, DELTA)
        assertEquals(0.8f, spans[2].startFraction, DELTA)
        assertEquals(1f, spans[2].endFraction, DELTA)
    }

    @Test
    fun `a zero length corrupt span is dropped instead of painting a negative width`() {
        // 两条记录的 PTS 相同：前一条的区间是 [0, 0)，在进度条上宽度是 0。
        val entries = listOf(
            entry(ptsUs = 0L, frame = 12, corrupt = true),
            entry(ptsUs = 0L, frame = 13, corrupt = true),
            entry(ptsUs = 1_000L, frame = 15)
        )

        val spans = rtpPreviewCorruptSpans(entries, 2_000L)
        assertEquals(1, spans.size)
        assertEquals(0f, spans.single().startFraction, DELTA)
        assertEquals(0.5f, spans.single().endFraction, DELTA)
    }

    @Test
    fun `a trailing corrupt access unit at the duration paints nothing`() {
        // 最后一条的 PTS 已经在时长上（例如时长被取整到帧边界）：区间被夹成零长度。
        val entries = listOf(
            entry(ptsUs = 0L, frame = 12),
            entry(ptsUs = 1_000L, frame = 13, corrupt = true)
        )

        assertTrue(rtpPreviewCorruptSpans(entries, 1_000L).isEmpty())
    }

    @Test
    fun `a non monotonic pair cannot produce a backwards span`() {
        // 下标 1 的 PTS 比它的下一条还大：区间被夹成 [2000, 2000) 而不是 [2000, 1000)。
        val entries = listOf(
            entry(ptsUs = 0L, frame = 12),
            entry(ptsUs = 2_000L, frame = 13, corrupt = true),
            entry(ptsUs = 1_000L, frame = 15, corrupt = true),
            entry(ptsUs = 3_000L, frame = 16)
        )

        val spans = rtpPreviewCorruptSpans(entries, 4_000L)
        assertEquals(1, spans.size)
        assertEquals(0.25f, spans.single().startFraction, DELTA)
        assertEquals(0.75f, spans.single().endFraction, DELTA)
        assertTrue(spans.all { it.endFraction > it.startFraction })
    }

    private fun entry(ptsUs: Long, frame: Int, corrupt: Boolean = false): VidxEntry = VidxEntry(
        offset = 0L,
        length = 8,
        ptsUs = ptsUs,
        firstFrame = frame,
        flags = if (corrupt) VidxFile.FLAG_CORRUPT else VidxFile.FLAG_KEY
    )

    private companion object {
        const val DELTA = 1e-6f
    }
}
