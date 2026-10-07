package com.example.layanalyzer.media

import com.example.layanalyzer.data.VideoParamSets
import java.util.Locale

/**
 * The video size a muxer will build its track with, and whether it had to
 * invent one.
 *
 * [usedFallback] is not decoration: the card requires a width/height of 0 to
 * fall back to 1280x720 *and to say so* rather than fall back silently, and a
 * pure function cannot log -- `android.util.Log` is "not mocked" in this
 * module's JVM unit tests, so any function a test executes must not reach it
 * (the same reason `SdpVideoParams.ParseResult` carries its counts back instead
 * of logging them, RTP5-KT-00). [RtpVideoMuxer] logs the warning where it reads
 * this flag, and the flag is what the unit test asserts on.
 */
data class VideoDimensions(val width: Int, val height: Int, val usedFallback: Boolean)

/**
 * The codec-specific data of one track: what goes into the MP4's `avcC` /
 * `hvcC` sample description box.
 *
 * [csd0] is always present. [csd1] is the second `csd` entry, which only H.264
 * uses (SPS in `csd-0`, PPS in `csd-1`); H.265 concatenates everything into
 * `csd-0` and leaves [csd1] null.
 *
 * `ByteArray` compares by reference, so this data class's generated
 * `equals`/`hashCode` are only true for the same instance. Tests compare the
 * octets with `assertArrayEquals` and the unit test does, deliberately.
 */
data class VideoCodecSpecificData(val csd0: ByteArray, val csd1: ByteArray?)

/**
 * The three container-level decisions RTP5-KT-01's muxer makes before it
 * touches `MediaMuxer`, as pure functions: the MIME type, the track size with
 * its fallback, and the `csd-0`/`csd-1` byte arrays.
 *
 * They live apart from [RtpVideoMuxer] because `MediaMuxer` is Android-only and
 * this machine has no device, so anything tangled into it is unverifiable here.
 * Nothing in this file imports `android.*`: the octets, the MIME strings and
 * the fallback are pinned by `VideoMuxFormatTest` on the JVM.
 *
 * The MIME strings are spelled out rather than taken from
 * `MediaFormat.MIMETYPE_VIDEO_AVC` / `MIMETYPE_VIDEO_HEVC`. They are the same
 * strings -- `MediaExtractor` reports exactly these for the track of a file
 * this muxer writes -- but reading a constant off an Android class would drag
 * that class into the JVM test for no gain, which is why `AacExporter` spells
 * out `audio/mp4a-latm` the same way.
 */
object VideoMuxFormat {

    // MPEG4Writer accepts this track-format key on Android 8+. Its default
    // video timescale is 90 kHz, which rounds away VideoSamplePlan's 1 us repairs.
    const val KEY_TIME_SCALE = "time-scale"
    const val TIME_SCALE = 1_000_000

    /** `MediaFormat.MIMETYPE_VIDEO_AVC`. */
    const val MIME_H264 = "video/avc"

    /** `MediaFormat.MIMETYPE_VIDEO_HEVC`. */
    const val MIME_H265 = "video/hevc"

    /**
     * The MIME of the **file** an MP4 muxed here is opened with (RTP5-KT-02).
     *
     * Not one of the two track MIMEs above: `video/avc` / `video/hevc` describe a
     * track inside the container and are what `MediaCodecList` and
     * `MediaExtractor` speak, while `video/mp4` is what an external player is
     * handed for the container itself. It lives here because this object owns
     * the video MIME vocabulary, so RTP5-KT-02 does not need a second constant
     * for it.
     */
    const val MIME_MP4 = "video/mp4"

    /** The card's fallback for a stream whose SPS could not be read. */
    const val FALLBACK_WIDTH = 1280
    const val FALLBACK_HEIGHT = 720

    /**
     * The Annex-B start code every parameter set is prefixed with, four octets
     * long.
     *
     * Four and not three: the card only bolds the start code for H.264's
     * `csd-0` ("SPS（**带 4 字节起始码**）"), but `task_rtp_m5_video.md` 5.2
     * says plainly that both H.264 entries carry one ("H.264 的 `csd-0`=SPS、
     * `csd-1`=PPS（都带起始码）"), and it has to: `MPEG4Writer` scans every `csd`
     * entry for start codes and treats the data as Annex-B, so a bare PPS in
     * `csd-1` would not be found at all. H.265's three concatenated sets get
     * one each for the same reason, which is what the card asks for there.
     * Four and not three because that is the form every
     * `sprop-parameter-sets` value is handed over in and the one the card names.
     */
    val START_CODE = byteArrayOf(0, 0, 0, 1)

    /** [START_CODE]'s length. */
    const val START_CODE_BYTES = 4

    /**
     * The `MediaFormat` MIME for a canonical codec id (README section 4.3), or
     * null for anything this muxer cannot write an MP4 around.
     *
     * `H265` and its alias `HEVC` are the same codec here, exactly as they are
     * in `SdpVideoParams.videoKind` (RTP5-KT-00) and `RtpCodecCatalog`, so the
     * two halves of M5 cannot disagree about which names mean HEVC. `PS` is
     * deliberately *not* accepted: a GB28181 access unit is an MPEG-2 program
     * stream whose elementary stream is H.264 or H.265, and a `.vidx` written
     * from one does not say which -- guessing would write an MP4 whose `avcC`
     * describes the wrong codec, so the caller has to resolve the codec first
     * and pass `H264`/`H265`.
     */
    fun mimeFor(codec: String): String? =
        when (codec.trim().lowercase(Locale.US)) {
            "h264" -> MIME_H264
            "h265", "hevc" -> MIME_H265
            else -> null
        }

    /**
     * The size the track is created with.
     *
     * A width or height that is not positive is the card's "0" case: NAT-05
     * leaves both at 0 when it could not read the SPS (it reports
     * `"widthSource":"unknown"` rather than guessing), and one of the pair being
     * 0 is the same request for the same reason -- a size is only meaningful as
     * a pair, so the whole pair is replaced, never half of it.
     */
    fun dimensions(width: Int, height: Int): VideoDimensions =
        if (width <= 0 || height <= 0) {
            VideoDimensions(FALLBACK_WIDTH, FALLBACK_HEIGHT, usedFallback = true)
        } else {
            VideoDimensions(width, height, usedFallback = false)
        }

    /**
     * `csd-0` and optionally `csd-1` for [paramSets] (RTP5-KT-00's SDP result),
     * or null when the sets this codec needs are not there.
     *
     * The shape, which the card fixes:
     *
     *  - H.264: `csd-0` = `00 00 00 01` + SPS, `csd-1` = `00 00 00 01` + PPS.
     *    One of each, because that is all an `avcC` holds; when the caller
     *    passes more than one (the type allows it, KT-00 does not produce it)
     *    the first of each is used, which is also the SDP convention KT-00
     *    follows.
     *  - H.265: `csd-0` = VPS + SPS + PPS, each with its own start code and in
     *    that order, and `csd-1` unused.
     *
     * Where the parameter sets come from is not this function's business -- the
     * card is explicit that they are `paramSets`, i.e. KT-00's SDP result, and
     * that the muxer must **not** re-scan the ES for them.
     *
     * Absence fails closed rather than muxing a track nothing can describe:
     * SPS and PPS are both required (an `avcC` is one SPS plus one PPS, and an
     * `hvcC` needs the same two to describe the stream), while the H.265 VPS is
     * optional because it is only one more array entry in `hvcC` and encoders
     * do omit it from SDP. A missing essential set is the caller's "缺少参数集"
     * answer, which is why null maps to a refusal and not to an empty `csd`.
     */
    fun codecSpecificData(codec: String, paramSets: VideoParamSets): VideoCodecSpecificData? {
        return when (mimeFor(codec)) {
            MIME_H264 -> {
                val sps = paramSets.sps.firstMeaningful() ?: return null
                val pps = paramSets.pps.firstMeaningful() ?: return null
                VideoCodecSpecificData(csd0 = withStartCode(sps), csd1 = withStartCode(pps))
            }

            MIME_H265 -> {
                val sps = paramSets.sps.firstMeaningful() ?: return null
                val pps = paramSets.pps.firstMeaningful() ?: return null
                val sets = ArrayList<ByteArray>(3)
                paramSets.vps.firstMeaningful()?.let { sets += withStartCode(it) }
                sets += withStartCode(sps)
                sets += withStartCode(pps)
                VideoCodecSpecificData(csd0 = concat(sets), csd1 = null)
            }

            else -> null
        }
    }

    /**
     * The first set a codec can actually use: `SdpVideoParams` never produces a
     * zero-octet one, but the type allows it, and a zero-octet SPS is a start
     * code followed by nothing -- the same absence as an empty list, and the
     * same answer.
     */
    private fun List<ByteArray>.firstMeaningful(): ByteArray? =
        firstOrNull { it.isNotEmpty() }

    /** `00 00 00 01` followed by [nal]. */
    fun withStartCode(nal: ByteArray): ByteArray =
        ByteArray(START_CODE_BYTES + nal.size).also { out ->
            START_CODE.copyInto(out)
            nal.copyInto(out, START_CODE_BYTES)
        }

    private fun concat(parts: List<ByteArray>): ByteArray {
        val out = ByteArray(parts.sumOf { it.size })
        var offset = 0
        for (part in parts) {
            part.copyInto(out, offset)
            offset += part.size
        }
        return out
    }
}
