// Copyright (c) 2026 cheig
// LayerAnalyzer - https://github.com/cheig/LayerAnalyzer
// Licensed under GNU GPL version 3; see LICENSE.

package com.example.layanalyzer.media

import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * RTP5-KT-04：对齐与交错这两条纯逻辑的单测。
 *
 * 这里断言的是**精确的微秒值**与**精确的写出顺序**：卡片要的对齐是一个数，而错一个
 * 符号或错一次取整就会让 MP4 的音频整体偏一秒（或者直接写不出来），所以每一个用例都
 * 用具体的微秒数把结论钉住，而不是断言「差不多」。
 *
 * 没有断言的东西：`MediaMuxer` 拿到这个计划之后写出什么。那需要设备，归属
 * `AudioVideoMuxerTest`（仪器测试，本机跑不了）。
 */
class AvMuxPlanTest {

    // ------------------------------------------------------------ 偏移量的符号

    @Test
    fun `the audio starts after the video and the offset is its first sample's pts`() {
        val plan = ok(
            video(0L, 33_333L, 66_666L),
            aac(0L, 20_000L),
            videoStartUs = 1_000_000L,
            audioStartUs = 1_500_000L
        )

        // 音频晚 0.5 s 开始 ⇒ 偏移 +500 000 µs。
        assertEquals(500_000L, plan.offsetUs)
        assertEquals(0, plan.droppedAudioSamples)
        // 卡片：「偏移量作为音频轨第一个样本的 PTS」。
        assertEquals(500_000L, plan.firstAudioPtsUs)
        val audio = plan.steps.filterIsInstance<AvMuxStep.Audio>()
        assertEquals(listOf(500_000L, 520_000L), audio.map { it.ptsUs })
        // 视频那一半一动不动：它是一个文件时间轴的零点。
        val video = plan.steps.filterIsInstance<AvMuxStep.Video>()
        assertEquals(listOf(0L, 33_333L, 66_666L), video.map { it.ptsUs })
    }

    @Test
    fun `both tracks start at the same instant and the offset is zero`() {
        val plan = ok(
            video(0L, 33_333L),
            aac(0L, 20_000L),
            videoStartUs = 1_700_000L,
            audioStartUs = 1_700_000L
        )

        assertEquals(0L, plan.offsetUs)
        assertEquals(0, plan.droppedAudioSamples)
        assertEquals(0L, plan.firstAudioPtsUs)
    }

    @Test
    fun `the audio starts before the video and the leading samples are dropped`() {
        // 48 kHz 的 AAC：一帧 1024 个样本 = 21 333 µs（整除后取整）。
        val samples = (0 until 20).map { index ->
            AacSample(index = index, ptsUs = index * 21_333L, length = 100)
        }
        val plan = ok(
            video(0L, 33_333L, 66_666L),
            samples,
            videoStartUs = 2_000_000L,
            audioStartUs = 1_700_000L
        )

        assertEquals(-300_000L, plan.offsetUs)
        // 音频第 14 个样本在 298 662 µs，加偏移仍是 -1 338；第 15 个在 319 995，
        // 落回 +19 995 —— 所以是 15 个被丢掉，第一个写出的在 19 995。
        assertEquals(15, plan.droppedAudioSamples)
        assertEquals(19_995L, plan.firstAudioPtsUs)
        assertEquals(20 - 15, plan.audioSamples)
        // 原始的负偏移照样报告出来：它说的是两条流真实的关系。
        assertEquals(-300_000L, plan.offsetUs)
        assertTrue("no written sample may be negative", plan.steps.all { it.ptsUs >= 0L })
    }

    @Test
    fun `a sample exactly on the video's zero is kept at pts zero`() {
        val plan = ok(
            video(0L),
            aac(100_000L, 200_000L, 300_000L, 400_000L),
            videoStartUs = 1_000_000L,
            audioStartUs = 700_000L
        )

        // 恰好落在 -offset 上的那个样本**不算**越界（判定是严格小于），保留在 0。
        assertEquals(2, plan.droppedAudioSamples)
        assertEquals(0L, plan.firstAudioPtsUs)
        assertEquals(listOf(0L, 100_000L), plan.steps.filterIsInstance<AvMuxStep.Audio>().map { it.ptsUs })
    }

    @Test
    fun `one microsecond before the video is still dropped`() {
        val plan = ok(
            video(0L),
            aac(299_999L, 300_000L),
            videoStartUs = 1_000_000L,
            audioStartUs = 700_000L
        )

        assertEquals(1, plan.droppedAudioSamples)
        assertEquals(0L, plan.firstAudioPtsUs)
    }

    // ---------------------------------------------------------------- 交错

    @Test
    fun `the two tracks are merged into one time ordered sequence`() {
        val plan = ok(
            video(0L, 33_333L, 66_666L),
            aac(10_000L, 40_000L),
            videoStartUs = 0L,
            audioStartUs = 0L
        )

        assertEquals(
            listOf(
                AvMuxStep.Video(VideoSample(0L, 10, 0L, 0)),
                AvMuxStep.Audio(0, 100, 10_000L),
                AvMuxStep.Video(VideoSample(1L, 10, 33_333L, 0)),
                AvMuxStep.Audio(1, 100, 40_000L),
                AvMuxStep.Video(VideoSample(2L, 10, 66_666L, 0))
            ),
            plan.steps
        )
        assertEquals(3, plan.videoSamples)
        assertEquals(2, plan.audioSamples)
    }

    @Test
    fun `the video step goes first when both tracks have a sample at the same time`() {
        val plan = ok(
            video(0L, 33_333L),
            aac(0L, 33_333L),
            videoStartUs = 0L,
            audioStartUs = 0L
        )

        assertEquals(
            listOf(
                AvMuxStep.Video(VideoSample(0L, 10, 0L, 0)),
                AvMuxStep.Audio(0, 100, 0L),
                AvMuxStep.Video(VideoSample(1L, 10, 33_333L, 0)),
                AvMuxStep.Audio(1, 100, 33_333L)
            ),
            plan.steps
        )
    }

    @Test
    fun `a tie is decided the same way after a negative offset shift`() {
        // 音频整体晚 10 000 µs，于是它的第 0 个样本正好落在视频的第 1 帧上。
        val plan = ok(
            video(0L, 10_000L, 20_000L),
            aac(0L),
            videoStartUs = 5_000_000L,
            audioStartUs = 5_010_000L
        )

        assertEquals(10_000L, plan.offsetUs)
        assertEquals(
            listOf(
                AvMuxStep.Video(VideoSample(0L, 10, 0L, 0)),
                AvMuxStep.Video(VideoSample(1L, 10, 10_000L, 0)),
                AvMuxStep.Audio(0, 100, 10_000L),
                AvMuxStep.Video(VideoSample(2L, 10, 20_000L, 0))
            ),
            plan.steps
        )
    }

    @Test
    fun `the audio steps keep their extractor indices when the head was dropped`() {
        val plan = ok(
            video(0L),
            aac(0L, 10L, 20L, 30L),
            videoStartUs = 1_000_000L,
            audioStartUs = 1_000_000L - 25L
        )

        assertEquals(3, plan.droppedAudioSamples)
        // 索引是提取器里那个样本的序号，不是「第几个写进去的」—— 封装器靠它前进。
        assertEquals(
            listOf(3),
            plan.steps.filterIsInstance<AvMuxStep.Audio>().map { it.index }
        )
    }

    @Test
    fun `the duration is the largest written presentation time over both tracks`() {
        val audioLast = ok(
            video(0L, 33_333L),
            aac(0L),
            videoStartUs = 0L,
            audioStartUs = 500_000L
        )
        assertEquals(500L, audioLast.durationMs)

        val videoLast = ok(
            video(0L, 900_000L),
            aac(0L, 20_000L),
            videoStartUs = 0L,
            audioStartUs = 0L
        )
        assertEquals(900L, videoLast.durationMs)
    }

    // ---------------------------------------------------------------- 拒绝

    @Test
    fun `an empty video plan is refused`() {
        assertEquals(
            AvMuxPlan.Rejected(AvMuxPlan.REASON_EMPTY_VIDEO),
            AvMuxPlan.of(emptyList(), aac(0L), 0L, 0L)
        )
    }

    @Test
    fun `an empty audio plan is refused`() {
        assertEquals(
            AvMuxPlan.Rejected(AvMuxPlan.REASON_EMPTY_AUDIO),
            AvMuxPlan.of(video(0L), emptyList(), 0L, 0L)
        )
    }

    @Test
    fun `the whole audio track falling before the video is refused`() {
        val plan = AvMuxPlan.of(
            video(0L),
            aac(0L, 10L, 20L),
            1_000_000L,
            0L
        )

        // 1 s 的偏移把三个样本全推到视频零点之前 ⇒ 没有音轨可加。
        assertEquals(AvMuxPlan.Rejected(AvMuxPlan.REASON_AUDIO_ALL_DROPPED), plan)
    }

    @Test
    fun `a track whose timestamps do not strictly increase is refused`() {
        assertEquals(
            AvMuxPlan.Rejected(AvMuxPlan.REASON_UNSORTED_VIDEO),
            AvMuxPlan.of(video(0L, 0L), aac(0L), 0L, 0L)
        )
        assertEquals(
            AvMuxPlan.Rejected(AvMuxPlan.REASON_UNSORTED_VIDEO),
            AvMuxPlan.of(video(10L, 5L), aac(0L), 0L, 0L)
        )
        assertEquals(
            AvMuxPlan.Rejected(AvMuxPlan.REASON_UNSORTED_AUDIO),
            AvMuxPlan.of(video(0L), aac(10L, 10L), 0L, 0L)
        )
    }

    @Test
    fun `an anchor that is not an anchor is refused instead of writing a 55 year file`() {
        // `firstAbsEpochUs` 没从原生层出来时读作 0：音频会被放到五十五年之外。
        assertEquals(
            AvMuxPlan.Rejected(AvMuxPlan.REASON_IMPLAUSIBLE_OFFSET),
            AvMuxPlan.of(video(0L), aac(0L), 0L, 1_700_000_000_000_000L)
        )
        // 反方向同样拒绝（这里会先撞上「音频整体在视频之前」，所以两个都是拒绝）。
        assertTrue(
            AvMuxPlan.of(video(0L), aac(0L), 1_700_000_000_000_000L, 0L)
                is AvMuxPlan.Rejected
        )
    }

    @Test
    fun `an audio time that would overflow the shift is refused`() {
        // 一个声称几十万年的 `stts`：加上正偏移之后溢出成负数 —— 不能写成负的
        // presentation time，所以整份计划拒绝（0.5 s 的偏移在最大偏移以内）。
        val huge = AacSample(index = 0, ptsUs = Long.MAX_VALUE - 1L, length = 100)

        assertEquals(
            AvMuxPlan.Rejected(AvMuxPlan.REASON_AUDIO_TIME_RANGE),
            AvMuxPlan.of(video(0L), listOf(huge), 0L, 500_000L)
        )
    }

    @Test
    fun `an offset of exactly one hour is still an offset`() {
        val plan = AvMuxPlan.of(
            video(0L),
            aac(0L),
            0L,
            AvMuxPlan.MAX_TRACK_OFFSET_US
        )

        assertTrue(plan is AvMuxPlan.Ok)
        assertEquals(AvMuxPlan.MAX_TRACK_OFFSET_US, (plan as AvMuxPlan.Ok).offsetUs)
    }

    // ---------------------------------------------------------------- 夹具

    private fun video(ptsUs: Long, vararg rest: Long): List<VideoSample> =
        (listOf(ptsUs) + rest.asList()).mapIndexed { index, pts ->
            VideoSample(offset = index.toLong(), length = 10, ptsUs = pts, flags = 0)
        }

    private fun aac(ptsUs: Long, vararg rest: Long): List<AacSample> =
        (listOf(ptsUs) + rest.asList()).mapIndexed { index, pts ->
            AacSample(index = index, ptsUs = pts, length = 100)
        }

    private fun ok(
        video: List<VideoSample>,
        audio: List<AacSample>,
        videoStartUs: Long,
        audioStartUs: Long
    ): AvMuxPlan.Ok {
        val plan = AvMuxPlan.of(video, audio, videoStartUs, audioStartUs)
        assertTrue("the plan was rejected: $plan", plan is AvMuxPlan.Ok)
        return plan as AvMuxPlan.Ok
    }
}
