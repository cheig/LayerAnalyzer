// Copyright (c) 2026 cheig
// LayerAnalyzer - https://github.com/cheig/LayerAnalyzer
// Licensed under GNU GPL version 3; see LICENSE.

package com.example.layanalyzer.ui.components.rtp

import com.example.layanalyzer.model.RtpVideoExportFormat
import com.example.layanalyzer.model.RtpVideoExportResult
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotEquals
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * RTP5-UI-01：视频流展示决策里的**纯**部分 —— 「哪条流算视频」「能导出哪几种产物」
 * 「点整张卡片该去哪里」「摘要上那几个数字怎么写」。
 *
 * 钉的都是会让界面说谎的那一类结论：把 PS 当成可导出的视频、把读不出来的宽高写成
 * `1280×720`（那是封装器的回退，不是这条流的分辨率）、把没数到的包型也列进摘要，
 * 以及把视频流送进音频播放器（那条路必然显示「不支持的流」）。
 */
class RtpVideoPresentationTest {

    @Test
    fun `the three native video ids are video and nothing else is`() {
        assertTrue(rtpStreamIsVideo("H264"))
        assertTrue(rtpStreamIsVideo("h265"))
        assertTrue(rtpStreamIsVideo(" H264 "))
        assertTrue(rtpStreamIsVideo("PS"))

        assertFalse(rtpStreamIsVideo("g711A"))
        assertFalse(rtpStreamIsVideo("opus"))
        assertFalse(rtpStreamIsVideo(""))
        // 别名不在这里展开：流上的编码已经被原生归一化成规范 ID（C13），收一套别名表
        // 会让「是不是视频」与「能不能导出」有两套名字。
        assertFalse(rtpStreamIsVideo("HEVC"))
    }

    @Test
    fun `PS is video but has no exportable product`() {
        // 这是本文件存在的理由：两个问题答案不同，菜单不能拿「是视频」当「能导出」用。
        assertTrue(rtpStreamIsVideo("PS"))
        assertTrue(rtpVideoExportFormats("PS").isEmpty())
    }

    @Test
    fun `the exportable formats are the two the native entry point accepts`() {
        assertEquals(
            listOf(RtpVideoExportFormat.MP4, RtpVideoExportFormat.RAW),
            rtpVideoExportFormats("H264")
        )
        assertEquals(rtpVideoExportFormats("H264"), rtpVideoExportFormats("h265"))
        assertTrue(rtpVideoExportFormats("g711A").isEmpty())
        assertTrue(rtpVideoExportFormats("").isEmpty())
    }

    @Test
    fun `tapping an audio card still opens the audio player`() {
        // 这一组是回归线：整卡点击改成走 rtpStreamCardTap 之前，音频流就是这条路径。
        assertEquals(
            RtpStreamCardTap.OpenAudioPlayer,
            rtpStreamCardTap("g711A", previewReady = false, hasPreviewFile = false)
        )
        // 预览状态为真也不能把音频流拐去预览页：判据里「是不是视频」排在「能不能播」前面。
        assertEquals(
            RtpStreamCardTap.OpenAudioPlayer,
            rtpStreamCardTap("opus", previewReady = true, hasPreviewFile = true)
        )
        // codec 未知（空/ 别名 / 未映射 PT）时按音频处理，与 rtpStreamIsVideo 同一个口径。
        assertEquals(
            RtpStreamCardTap.OpenAudioPlayer,
            rtpStreamCardTap("", previewReady = true, hasPreviewFile = true)
        )
    }

    @Test
    fun `tapping a video card never reaches the audio player`() {
        // 这就是回归本身：H.264 点进去曾经一路走到音频播放器，而那张路由表里
        // H.264 是 UNSUPPORTED，于是播放器页显示「不支持的流」。
        assertEquals(
            RtpStreamCardTap.PrepareAndPreview,
            rtpStreamCardTap("H264", previewReady = false, hasPreviewFile = false)
        )
        assertEquals(
            RtpStreamCardTap.PrepareAndPreview,
            rtpStreamCardTap("h265", previewReady = false, hasPreviewFile = false)
        )
        // PS 也关在音频播放器门外 —— 这半条与「它能不能导出」无关：整卡点击的第一道
        // 判据是`rtpStreamIsVideo`，PS 成立，所以它绝不会掉到 OpenAudioPlayer 上。
        //
        // 注意这里**不**断言「PS 永远 PrepareAndPreview」：一旦宿主真的记账了（两个条件
        // 都为真），整卡点击就该与 ⋮ 菜单的「应用内预览」同口径地进预览页，而菜单的
        // 判据（`RtpStreamsScreen.kt` 的 `previewReady && id in previewStreamIds`）
        // 并不查导出格式表。在整卡点击里多加那一层会造出「菜单里没有预览项、点卡片
        // 却进了预览页」的不一致 —— 那才是真的说谎。
        //
        // 现实里这个分支对 PS 不可达：`rtpVideoExportFormats("PS")` 是空表，导出菜单
        // 项对它置灰，MP4 永远导不出来，宿主也就永远不会记账。
        assertEquals(
            RtpStreamCardTap.PrepareAndPreview,
            rtpStreamCardTap("PS", previewReady = false, hasPreviewFile = false)
        )
    }

    @Test
    fun `a video card with no MP4 yet prepares one instead of asking for the menu`() {
        // RTP5-UI-01 的第二版：整卡点击是**唯一**的自然入口，让用户自己去 ⋮ 菜单里
        // 导出等于把「点一下」拆成四步（找菜单 → 点导出 → 选格式 → 选保存位置）。
        // `prepareVideoPreview` 复用的是 SAF 导出同一段封装实现，中间产物只写缓存。
        //
        // 关键性质不在这条断言本身，而在它**不是** OpenAudioPlayer：封装失败时 UI 显示
        // `RtpVideoOpenUiState.Error` 的原文，绝不退回音频播放器 —— 那条路后面是
        // `decodeAudio()`，H.264 在路由表里是 UNSUPPORTED，于是又落回「不支持的流」。
        assertNotEquals(
            RtpStreamCardTap.OpenAudioPlayer,
            rtpStreamCardTap("H264", previewReady = false, hasPreviewFile = false)
        )
    }

    @Test
    fun `a video card opens the preview only when both halves agree`() {
        // 与 ⋮ 菜单里「应用内预览」同一个交集：设备能播 + 文件属于这条流。
        assertEquals(
            RtpStreamCardTap.OpenVideoPreview,
            rtpStreamCardTap("H264", previewReady = true, hasPreviewFile = true)
        )
        // 两个来源缺一个都不行 —— 与菜单项的可见性是同一条判据（UI-01 的原话：
        // 「有就显示、没有就不显示」，不给按不动的灰按钮）。
        assertEquals(
            RtpStreamCardTap.PrepareAndPreview,
            rtpStreamCardTap("H264", previewReady = true, hasPreviewFile = false)
        )
        assertEquals(
            RtpStreamCardTap.PrepareAndPreview,
            rtpStreamCardTap("H264", previewReady = false, hasPreviewFile = true)
        )
    }

    @Test
    fun `a resolution is only printed when the SPS really gave one`() {
        assertEquals("1280×720", rtpVideoResolutionText(result(width = 1280, height = 720)))
        assertEquals("720×1280", rtpVideoResolutionText(result(width = 720, height = 1280)))

        // NAT-05 读不出 SPS 时两个都是 0 且带 widthSource=unknown。
        assertNull(rtpVideoResolutionText(result(width = 0, height = 0, widthSource = "unknown")))
        // 只有一半是 0 也是「不知道」（NAT-05 decision 11 的同一条口径）。
        assertNull(rtpVideoResolutionText(result(width = 1280, height = 0)))
        assertNull(rtpVideoResolutionText(result(width = 0, height = 720)))
        // 标了 unknown 就是 unknown，即使数字看着像真的。
        assertNull(
            rtpVideoResolutionText(result(width = 1280, height = 720, widthSource = "unknown"))
        )
    }

    @Test
    fun `unsupported packet types list only the ones with a count`() {
        // 原生预置的四个恒为 0 的键（STAP-B/MTAP16/FU-B/PACI）一个都不该出现。
        assertEquals(
            "",
            rtpVideoUnsupportedNalText(
                mapOf("STAP-B" to 0L, "MTAP16" to 0L, "FU-B" to 0L, "PACI" to 0L)
            )
        )
        assertEquals("", rtpVideoUnsupportedNalText(emptyMap()))

        assertEquals("FU-B 2", rtpVideoUnsupportedNalText(mapOf("FU-B" to 2L)))
        assertEquals(
            "FU-B 2 · STAP-B 1",
            rtpVideoUnsupportedNalText(mapOf("STAP-B" to 1L, "FU-B" to 2L))
        )
        // 契约之外的键（NAT-05 decision 14 说原生会追加它真的数到的类型）照样列出来。
        assertEquals("AP(DONL) 1 · type31 3", rtpVideoUnsupportedNalText(mapOf("type31" to 3L, "AP(DONL)" to 1L)))
    }

    @Test
    fun `the summary row carries the total and then the breakdown`() {
        // 没有数到任何不支持包型：就是 `0`，不写一对空的括号。
        assertEquals("0", rtpVideoUnsupportedNalSummary(result()))
        // 总数取自 unsupportedNalPackets（预置键不算数），明细跟在括号里。
        assertEquals(
            "3 (FU-B 2 · STAP-B 1)",
            rtpVideoUnsupportedNalSummary(
                result(unsupportedNalCounts = mapOf("STAP-B" to 1L, "FU-B" to 2L))
            )
        )
    }

    private fun result(
        width: Int = 0,
        height: Int = 0,
        widthSource: String = "",
        unsupportedNalCounts: Map<String, Long> = emptyMap()
    ): RtpVideoExportResult = RtpVideoExportResult(
        width = width,
        height = height,
        widthSource = widthSource,
        unsupportedNalCounts = unsupportedNalCounts
    )
}
