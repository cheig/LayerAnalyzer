package com.example.layanalyzer.media

import com.example.layanalyzer.data.LinkedRtpStream
import com.example.layanalyzer.data.RtpLinkReason
import com.example.layanalyzer.data.RtpStreamDirection
import com.example.layanalyzer.data.VoipCall
import com.example.layanalyzer.data.VoipCallState
import com.example.layanalyzer.model.RtpCodecSource
import com.example.layanalyzer.model.RtpDecodability
import com.example.layanalyzer.model.RtpStream
import java.util.Locale
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Test

/**
 * RTP5-KT-04：可用性判定的单测。五个非 `Ready` 取值一个一例，外加「先问哪个」的
 * 顺序 —— 一个「没有呼叫」被报成「设备没有编码器」会让人去查错方向。
 *
 * M3 的结果在这里是用手搭的 `VoipCall`，不是跑一遍 `RtpCallLinker`：本函数只**查**
 * 关联结果，不产生它，所以它的输入就该是可以直接摆出来的数据。关联本身的对错由
 * `RtpCallLinkerTest` 负责。
 */
class AvMuxAvailabilityTest {

    @Test
    fun `a video stream in no call has no entry`() {
        assertEquals(
            RtpAvMuxAvailability.NoCall,
            rtpAvMuxAvailability(
                videoStream = stream("v0", "H264"),
                calls = emptyList(),
                aacEncoderAvailable = true
            )
        )
    }

    @Test
    fun `a video stream the calls do not mention has no entry`() {
        val call = call("c1", linked(stream("a0", "g711A"), RtpStreamDirection.FORWARD))

        assertEquals(
            RtpAvMuxAvailability.NoCall,
            rtpAvMuxAvailability(stream("v0", "H264"), listOf(call), aacEncoderAvailable = true)
        )
    }

    @Test
    fun `a call with no audio has no entry`() {
        val call = call("c1", linked(stream("v0", "H264"), RtpStreamDirection.FORWARD))

        assertEquals(
            RtpAvMuxAvailability.CallHasNoAudio("c1"),
            rtpAvMuxAvailability(stream("v0", "H264"), listOf(call), aacEncoderAvailable = true)
        )
    }

    @Test
    fun `streams that cannot be rendered to a wav are not audio`() {
        val call = call(
            "c1",
            linked(stream("v0", "H264"), RtpStreamDirection.FORWARD),
            // 事件编码与另一条视频都不是音轨：导出表里都没有 WAV。
            linked(stream("e0", "telephone-event"), RtpStreamDirection.FORWARD),
            linked(stream("v1", "H265"), RtpStreamDirection.REVERSE)
        )

        assertEquals(
            RtpAvMuxAvailability.CallHasNoAudio("c1"),
            rtpAvMuxAvailability(stream("v0", "H264"), listOf(call), aacEncoderAvailable = true)
        )
    }

    @Test
    fun `an audio stream that cannot be decoded has no wav`() {
        val call = call(
            "c1",
            linked(stream("v0", "H264"), RtpStreamDirection.FORWARD),
            linked(
                stream("a0", "g711A", decodable = RtpDecodability.SRTP),
                RtpStreamDirection.REVERSE
            )
        )

        assertEquals(
            RtpAvMuxAvailability.NoRenderedWav("a0"),
            rtpAvMuxAvailability(stream("v0", "H264"), listOf(call), aacEncoderAvailable = true)
        )
    }

    @Test
    fun `a stream that is not a video codec has no video export`() {
        val call = call(
            "c1",
            linked(stream("a0", "g711A"), RtpStreamDirection.FORWARD),
            linked(stream("n0", "g729"), RtpStreamDirection.REVERSE)
        )

        // 拿一条音频流当「视频流」问：音频那半满足，视频这半不满足。
        assertEquals(
            RtpAvMuxAvailability.NoVideoExport,
            rtpAvMuxAvailability(stream("n0", "g729"), listOf(call), aacEncoderAvailable = true)
        )
    }

    @Test
    fun `a video stream that cannot be decoded has no video export`() {
        // 同一个实例：可用性读的是调用方问的那条流自己的 `decodable`（生产里它就在
        // M3 的结果里，是同一个对象）。
        val video = stream("v0", "H264", decodable = RtpDecodability.TRUNCATED)
        val call = call(
            "c1",
            linked(video, RtpStreamDirection.FORWARD),
            linked(stream("a0", "g711A"), RtpStreamDirection.REVERSE)
        )

        assertEquals(
            RtpAvMuxAvailability.NoVideoExport,
            rtpAvMuxAvailability(video, listOf(call), aacEncoderAvailable = true)
        )
    }

    @Test
    fun `a device without an aac encoder has no entry`() {
        val call = completeCall()

        assertEquals(
            RtpAvMuxAvailability.NoAacEncoder,
            rtpAvMuxAvailability(stream("v0", "H264"), listOf(call), aacEncoderAvailable = false)
        )
    }

    @Test
    fun `a failed encoder query is not a missing encoder`() {
        val call = completeCall()

        assertEquals(
            RtpAvMuxAvailability.Ready("c1", "a0"),
            rtpAvMuxAvailability(stream("v0", "H264"), listOf(call), aacEncoderAvailable = null)
        )
    }

    @Test
    fun `a linked call with audio and a video export is ready`() {
        val call = completeCall()

        assertEquals(
            RtpAvMuxAvailability.Ready(callId = "c1", audioStreamId = "a0"),
            rtpAvMuxAvailability(stream("v0", "H264"), listOf(call), aacEncoderAvailable = true)
        )
    }

    @Test
    fun `the call is looked up by the video stream's own id`() {
        val other = completeCall()
        val mine = linkedCall(callId = "c2", videoId = "v9", audioId = "a9")

        assertEquals(
            RtpAvMuxAvailability.Ready("c2", "a9"),
            rtpAvMuxAvailability(stream("v9", "H264"), listOf(other, mine), aacEncoderAvailable = true)
        )
        assertNull(linkedCallFor("v0", emptyList()))
        assertEquals("c2", linkedCallFor("v9", listOf(other, mine))?.callId)
    }

    @Test
    fun `the reasons are asked in order and the audio is decided before the video`() {
        // 一个只有视频流、没有任何音频的呼叫。
        val videoOnly = call("c1", linked(stream("v0", "H264"), RtpStreamDirection.FORWARD))

        // 没有呼叫 ⇒ 先报 NoCall，哪怕后面的设备能力也不成立。
        assertEquals(
            RtpAvMuxAvailability.NoCall,
            rtpAvMuxAvailability(stream("v0", "H264"), emptyList(), aacEncoderAvailable = false)
        )
        // 有呼叫但没有音频 ⇒ 报 CallHasNoAudio，而不是「设备没有编码器」。
        assertEquals(
            RtpAvMuxAvailability.CallHasNoAudio("c1"),
            rtpAvMuxAvailability(stream("v0", "H264"), listOf(videoOnly), aacEncoderAvailable = false)
        )
    }

    @Test
    fun `the audio stream is the forward one, then the reverse one, then the first`() {
        val forward = stream("a-fwd", "g711A")
        val reverse = stream("a-rev", "g711A")
        val unknown = stream("a-unk", "g711A")

        assertEquals(
            "a-fwd",
            primaryAudioStream(
                call(
                    "c1",
                    linked(reverse, RtpStreamDirection.REVERSE),
                    linked(forward, RtpStreamDirection.FORWARD),
                    linked(unknown, RtpStreamDirection.UNKNOWN)
                )
            )?.id
        )
        assertEquals(
            "a-rev",
            primaryAudioStream(
                call(
                    "c1",
                    linked(unknown, RtpStreamDirection.UNKNOWN),
                    linked(reverse, RtpStreamDirection.REVERSE)
                )
            )?.id
        )
        assertEquals(
            "a-unk",
            primaryAudioStream(call("c1", linked(unknown, RtpStreamDirection.UNKNOWN)))?.id
        )
        assertNull(primaryAudioStream(call("c1", linked(stream("v0", "H264"), RtpStreamDirection.FORWARD))))
    }

    // ---------------------------------------------------------------- 夹具

    private fun completeCall(): VoipCall = linkedCall(callId = "c1", videoId = "v0", audioId = "a0")

    private fun linkedCall(callId: String, videoId: String, audioId: String): VoipCall = call(
        callId,
        linked(stream(videoId, "H264"), RtpStreamDirection.REVERSE),
        linked(stream(audioId, "g711A"), RtpStreamDirection.FORWARD)
    )

    private fun call(callId: String, vararg streams: LinkedRtpStream): VoipCall = VoipCall(
        callId = callId, from = "", to = "", state = VoipCallState.IN_CALL,
        startRel = 0.0, setupMs = null, ringMs = null, durationMs = null,
        sipFrames = emptyList(), sdpFrames = emptyList(),
        streams = streams.toList(), mos = null
    )

    private fun linked(stream: RtpStream, direction: RtpStreamDirection): LinkedRtpStream =
        LinkedRtpStream(
            stream = stream,
            direction = direction,
            linkReason = RtpLinkReason.SDP_ADDRESS_PORT,
            callId = ""
        )

    /** 只覆盖本卡关心的字段，其余给固定默认值；`ssrcHex` 由 `ssrc` 推导。 */
    private fun stream(
        id: String,
        codec: String,
        decodable: RtpDecodability = RtpDecodability.YES,
        firstAbsEpochUs: Long = 0L
    ): RtpStream = RtpStream(
        id = id,
        src = "10.0.0.1", srcPort = 40000, dst = "10.0.0.2", dstPort = 30000,
        ssrc = 1L, ssrcHex = String.format(Locale.US, "0x%08x", 1L),
        pt = 97, codec = codec, codecSource = RtpCodecSource.SDP, clockRate = 90000,
        setupFrame = 0L, setupMethod = "", isSrtp = false,
        packets = 0L, expected = 0L, lost = 0L, lostPct = 0.0,
        seqErrors = 0L, outOfOrder = 0L, truncated = 0L, problem = false,
        minDeltaMs = 0.0, meanDeltaMs = 0.0, maxDeltaMs = 0.0, maxDeltaFrame = 0L,
        minJitterMs = null, meanJitterMs = null, maxJitterMs = null, jitterAvailable = false,
        maxSkewMs = 0.0, bytes = 0L,
        firstFrame = 0L, lastFrame = 0L, startRel = 0.0, endRel = 0.0,
        firstAbsEpochUs = firstAbsEpochUs,
        ptsSeen = emptyList(), decodable = decodable, decodableReason = "",
        primaryPayloadType = 97
    )
}
