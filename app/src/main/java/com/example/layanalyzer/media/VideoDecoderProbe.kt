package com.example.layanalyzer.media

import android.media.MediaCodecList
import android.media.MediaFormat

/**
 * RTP5-KT-02: whether this device has a decoder for one MIME.
 *
 * `null` means the query itself failed (the platform threw), which is *not* the
 * same answer as `false` -- see `RtpVideoDecoderAvailability.UNKNOWN`. The
 * decision that turns this into a user-visible notice is a pure function in
 * `model/RtpModels.kt` (`rtpVideoDecoderAvailability`), so the JVM tests can pin
 * "no decoder ⇒ notice + still exportable" without a device.
 */
fun interface VideoDecoderProbe {
    fun hasDecoder(mime: String): Boolean?
}

/**
 * The production [VideoDecoderProbe] -- the one `android.media.*` call of
 * RTP5-KT-02, and it is deliberately this thin.
 *
 * The size handed to `createVideoFormat` is the muxer's 1280x720 fallback
 * (`VideoMuxFormat`): `findDecoderForFormat` matches on the MIME and the
 * codec's advertised capabilities, and RTP5-KT-01 calls the same fallback for a
 * stream whose SPS could not be read, so the two halves ask the same question.
 * A format for a MIME no codec claims, a missing codec list -- anything the
 * framework throws is reported as "cannot tell" rather than as "no decoder".
 */
object PlatformVideoDecoderProbe : VideoDecoderProbe {
    override fun hasDecoder(mime: String): Boolean? = try {
        MediaCodecList(MediaCodecList.REGULAR_CODECS).findDecoderForFormat(
            MediaFormat.createVideoFormat(
                mime,
                VideoMuxFormat.FALLBACK_WIDTH,
                VideoMuxFormat.FALLBACK_HEIGHT
            )
        ) != null
    } catch (_: Exception) {
        null
    }
}
