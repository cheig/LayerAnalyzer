package com.example.layanalyzer.media

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * RTP5-KT-01: the `.vidx` records turned into a sample timeline.
 *
 * This is the half of the muxer that decides what a player will see -- which
 * byte range is a sample, what its timestamp is, and whether it is a key frame
 * -- and it is pure Kotlin on purpose, because `MediaMuxer` cannot be run on
 * this machine and a bug in the timeline is not something the container can
 * report: `MediaMuxer` writes whatever timestamps it is handed, so a missing
 * monotonic-PTS repair shows up as a track that will not play rather than as an
 * error.
 *
 * The two rules the card fixes are asserted directly: `flags & 0x01` is a key
 * frame (and the other two bits the format defines are *not* muxer flags), and
 * a PTS that is equal to or smaller than the previous *written* one becomes
 * `previous + 1` and is counted.
 *
 * The `shortStream` case is the one the card does not spell out but the
 * muxer needs: an index and an ES that disagree about the size of the ES are a
 * truncated or stale pair, and the samples that do fit are not a subset worth
 * writing.
 */
class VideoSamplePlanTest {

    @Test
    fun `a well-ordered index becomes one sample per record, ranges not copies`() {
        val entries = listOf(
            entry(offset = 0, length = 8, ptsUs = 0, flags = VidxFile.FLAG_KEY),
            entry(offset = 8, length = 12, ptsUs = 33_333),
            entry(offset = 20, length = 9, ptsUs = 66_666, flags = VidxFile.FLAG_KEY)
        )

        val plan = ok(VideoSamplePlan.of(entries, streamBytes = 1_000))

        assertEquals(3, plan.samples.size)
        assertEquals(listOf(0L, 8L, 20L), plan.samples.map { it.offset })
        assertEquals(listOf(8, 12, 9), plan.samples.map { it.length })
        assertEquals(listOf(0L, 33_333L, 66_666L), plan.samples.map { it.ptsUs })
        assertEquals(0, plan.nonMonotonicPtsCount)
        assertEquals("the last written PTS is the duration", 66L, plan.durationMs)
    }

    @Test
    fun `the key frame bit is flag 0x01 and only flag 0x01`() {
        val entries = listOf(
            entry(ptsUs = 0, flags = VidxFile.FLAG_KEY),
            entry(ptsUs = 1, flags = VidxFile.FLAG_CORRUPT),
            entry(ptsUs = 2, flags = VidxFile.FLAG_PARAM_SETS),
            entry(ptsUs = 3, flags = VidxFile.FLAG_CORRUPT or VidxFile.FLAG_PARAM_SETS),
            entry(ptsUs = 4, flags = VidxFile.FLAG_KEY or VidxFile.FLAG_CORRUPT),
            entry(ptsUs = 5, flags = 0x00)
        )

        val plan = ok(VideoSamplePlan.of(entries, streamBytes = 1_000))

        assertEquals(
            "only the record with bit 0x01 is a key frame",
            listOf(true, false, false, false, true, false),
            plan.samples.map { it.isKeyFrame }
        )
        // The muxer flags are `MediaCodec.BufferInfo` flags: the key frame bit
        // is 1 and nothing else is set, because corrupt and parameter-set are
        // properties of the file, not of the container.
        assertEquals(
            listOf(1, 0, 0, 0, 1, 0),
            plan.samples.map { it.flags }
        )
        assertEquals(1, VideoSamplePlan.KEY_FRAME_FLAG)
    }

    @Test
    fun `a PTS that goes backwards is pushed one microsecond past the previous one`() {
        val entries = listOf(
            entry(ptsUs = 0),
            entry(ptsUs = 100_000),
            entry(ptsUs = 50_000),
            entry(ptsUs = 200_000)
        )

        val plan = ok(VideoSamplePlan.of(entries, streamBytes = 1_000))

        assertEquals(
            listOf(0L, 100_000L, 100_001L, 200_000L),
            plan.samples.map { it.ptsUs }
        )
        assertEquals(1, plan.nonMonotonicPtsCount)
    }

    @Test
    fun `an equal PTS is repaired the same way as a smaller one`() {
        val entries = listOf(entry(ptsUs = 7_000), entry(ptsUs = 7_000))

        val plan = ok(VideoSamplePlan.of(entries, streamBytes = 1_000))

        assertEquals(listOf(7_000L, 7_001L), plan.samples.map { it.ptsUs })
        assertEquals(1, plan.nonMonotonicPtsCount)
    }

    @Test
    fun `a run of equal or decreasing PTS advances one microsecond at a time`() {
        // The repair compares against the value that was *written*, not against
        // the previous record's raw PTS -- otherwise a run of three would all
        // land on the same microsecond and `MediaMuxer` would still reject it.
        val entries = listOf(
            entry(ptsUs = 5_000),
            entry(ptsUs = 5_000),
            entry(ptsUs = 5_000),
            entry(ptsUs = 4_999),
            entry(ptsUs = 5_000)
        )

        val plan = ok(VideoSamplePlan.of(entries, streamBytes = 1_000))

        assertEquals(
            listOf(5_000L, 5_001L, 5_002L, 5_003L, 5_004L),
            plan.samples.map { it.ptsUs }
        )
        assertEquals(4, plan.nonMonotonicPtsCount)
    }

    @Test
    fun `the duration is the last repaired PTS, not the last raw one`() {
        val entries = listOf(
            entry(ptsUs = 0),
            entry(ptsUs = 40_000),
            entry(ptsUs = 1_000)
        )

        val plan = ok(VideoSamplePlan.of(entries, streamBytes = 1_000))

        assertEquals(40_001L, plan.samples.last().ptsUs)
        assertEquals(40L, plan.durationMs)
    }

    @Test
    fun `a stream whose first PTS is not zero is left alone`() {
        // NAT-03 numbers from the first access unit, so this is not the normal
        // case; the plan must not invent a rule the card does not have, it must
        // only refuse to go *backwards*.
        val plan = ok(
            VideoSamplePlan.of(listOf(entry(ptsUs = 2_000), entry(ptsUs = 3_000)), 1_000)
        )

        assertEquals(listOf(2_000L, 3_000L), plan.samples.map { it.ptsUs })
        assertEquals(0, plan.nonMonotonicPtsCount)
    }

    @Test
    fun `a byte range that does not fit the elementary stream is refused`() {
        val entries = listOf(entry(offset = 0, length = 8), entry(offset = 8, length = 8))

        assertEquals(
            VideoSamplePlan.REASON_SHORT_STREAM,
            rejected(VideoSamplePlan.of(entries, streamBytes = 15))
        )
        assertTrue(
            "a range ending exactly at the end of the file fits",
            VideoSamplePlan.of(entries, 16) is VideoSamplePlan.Ok
        )
    }

    @Test
    fun `an offset beyond the stream is refused`() {
        assertEquals(
            VideoSamplePlan.REASON_SHORT_STREAM,
            rejected(VideoSamplePlan.of(listOf(entry(offset = 32, length = 1)), 32))
        )
    }

    @Test
    fun `an absurd offset is refused without overflowing the range check`() {
        // `offset + length` would wrap to a value that looks small; the check
        // has to be a subtraction so this cannot slip through.
        assertEquals(
            VideoSamplePlan.REASON_SHORT_STREAM,
            rejected(
                VideoSamplePlan.of(
                    listOf(entry(offset = Long.MAX_VALUE, length = 1_000)),
                    streamBytes = 4_096
                )
            )
        )
    }

    @Test
    fun `a record that describes no sample is refused`() {
        assertEquals(
            "a zero-length access unit is not a frame",
            VideoSamplePlan.REASON_BAD_RECORD,
            rejected(VideoSamplePlan.of(listOf(entry(length = 0)), 1_000))
        )
        assertEquals(
            "a negative length is what a u32 above 2^31 reads back as",
            VideoSamplePlan.REASON_BAD_RECORD,
            rejected(VideoSamplePlan.of(listOf(entry(length = -2)), 1_000))
        )
        assertEquals(
            VideoSamplePlan.REASON_BAD_RECORD,
            rejected(VideoSamplePlan.of(listOf(entry(offset = -1)), 1_000))
        )
    }

    @Test
    fun `an index with no records is refused`() {
        assertEquals(
            VideoSamplePlan.REASON_EMPTY_INDEX,
            rejected(VideoSamplePlan.of(emptyList(), streamBytes = 0))
        )
    }

    @Test
    fun `the plan is rejected as a whole, never partially`() {
        // The first two records are fine and the third is not: the answer is a
        // refusal, not the two good samples.
        val entries = listOf(
            entry(offset = 0, length = 4, ptsUs = 0),
            entry(offset = 4, length = 4, ptsUs = 1),
            entry(offset = 8, length = 400, ptsUs = 2)
        )

        assertEquals(
            VideoSamplePlan.REASON_SHORT_STREAM,
            rejected(VideoSamplePlan.of(entries, streamBytes = 16))
        )
    }

    @Test
    fun `the repair counter is zero for an index that is already increasing`() {
        val entries = (0 until 10).map { entry(offset = it * 4L, length = 4, ptsUs = it * 33_333L) }

        val plan = ok(VideoSamplePlan.of(entries, streamBytes = 40))

        assertEquals(0, plan.nonMonotonicPtsCount)
        assertEquals(299_997L, plan.samples.last().ptsUs)
        assertEquals(299L, plan.durationMs)
    }

    @Test
    fun `a corrupt key frame keeps its key flag`() {
        // The corrupt bit does not clear the key bit, and both arrive together
        // from a stream with a lost packet inside an IDR.
        val plan = ok(
            VideoSamplePlan.of(
                listOf(entry(flags = VidxFile.FLAG_KEY or VidxFile.FLAG_CORRUPT)),
                1_000
            )
        )

        assertTrue(plan.samples.single().isKeyFrame)
        assertFalse("the muxer has no flag for corrupt", plan.samples.single().flags and 0x02 != 0)
    }

    // ---------------------------------------------------------------- helpers

    private fun ok(plan: VideoSamplePlan): VideoSamplePlan.Ok =
        plan as? VideoSamplePlan.Ok ?: throw AssertionError("expected a plan, got $plan")

    private fun rejected(plan: VideoSamplePlan): String =
        (plan as? VideoSamplePlan.Rejected)?.reason
            ?: throw AssertionError("expected a refusal, got $plan")

    private fun entry(
        offset: Long = 0,
        length: Int = 4,
        ptsUs: Long = 0,
        flags: Int = 0
    ) = VidxEntry(offset = offset, length = length, ptsUs = ptsUs, firstFrame = 1, flags = flags)
}
