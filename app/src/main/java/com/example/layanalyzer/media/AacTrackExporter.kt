package com.example.layanalyzer.media

import android.media.MediaCodecInfo
import android.media.MediaCodecList
import android.media.MediaFormat
import java.io.File

/**
 * RTP5-KT-04: whether this device has an AAC encoder at all.
 *
 * `null` means the query itself failed (the platform threw), which is *not* the
 * same answer as `false` -- see [RtpAvMuxAvailability]'s fail-open rule. This is
 * the only question RTP5-KT-04 asks the codec list, and it is a **query**: the
 * card's availability decision must not run the encoder, and this does not.
 */
fun interface AacEncoderProbe {
    fun hasEncoder(): Boolean?
}

/**
 * The production [AacEncoderProbe] -- the one `android.media.*` call of
 * RTP5-KT-04, and it is deliberately this thin.
 *
 * The format is a generic 48 kHz stereo AAC-LC: the question is "does this
 * device have the encoder M4-KT-04 needs", not "will it accept this particular
 * WAV", and a per-file answer cannot be had without running the encoder. The
 * per-file answer is `AacExporter`'s own (`AacExportResult.Unsupported`), which
 * is why an availability of `Ready` is a permission rather than a promise.
 *
 * What is asked is exactly what `AacExporter` asks of the platform: the same
 * `MIME_AAC`, the same `AACObjectLC` profile and the same bit rate, so the two
 * halves of this milestone cannot look for different encoders. A missing codec
 * list, or anything else the framework throws, is reported as "cannot tell"
 * rather than as "no encoder".
 */
object PlatformAacEncoderProbe : AacEncoderProbe {
    override fun hasEncoder(): Boolean? = try {
        val format = MediaFormat
            .createAudioFormat(AacExporter.MIME_AAC, PROBE_SAMPLE_RATE, PROBE_CHANNELS)
            .apply {
                setInteger(
                    MediaFormat.KEY_AAC_PROFILE,
                    MediaCodecInfo.CodecProfileLevel.AACObjectLC
                )
                setInteger(MediaFormat.KEY_BIT_RATE, AacExporter.BIT_RATE)
            }
        MediaCodecList(MediaCodecList.REGULAR_CODECS).findEncoderForFormat(format) != null
    } catch (_: Exception) {
        null
    }

    /** A capability probe's own format, not a statement about the WAV. */
    private const val PROBE_SAMPLE_RATE = 48_000
    private const val PROBE_CHANNELS = 2
}

/**
 * RTP5-KT-04: the seam between `RtpViewModel` and M4-KT-04's `AacExporter`.
 *
 * It exists for the same reason [VideoMuxer] does: the JVM unit tests of the
 * view model must be able to see *that* a rendered WAV was handed to an AAC
 * encoder, towards which path, and what came back -- and [AacExporter] cannot
 * run there at all, because it is built on `MediaCodec` and `MediaMuxer` and
 * this module's `android.*` is a "not mocked" stub. The signature is
 * [AacExporter.export]'s, one for one.
 */
interface AacTrackExporter {
    suspend fun export(
        wavFile: File,
        outFile: File,
        onProgress: ((done: Int, total: Int) -> Unit)? = null
    ): AacExportResult

    /** Asks a running [export] to stop and clean up; a no-op when nothing is running. */
    fun cancel()
}

/**
 * The production [AacTrackExporter]: a fresh [AacExporter] per call.
 *
 * Fresh per call, not one shared instance, and that is not an optimisation
 * detail -- [AacExporter.cancel] latches its flag, so a shared exporter would
 * let one cancelled combination poison every one after it with `cancelled`.
 * The instance a call is running on is remembered only so [cancel] has
 * something to reach.
 *
 * It does not reimplement, re-check or re-wrap anything: [AacExporter] already
 * owns the ADTS question, the `csd-0` construction and the promise that no file
 * survives a call that did not succeed, and the card words this route as "run
 * the WAV through `AacExporter`".
 */
class PlatformAacTrackExporter : AacTrackExporter {

    @Volatile
    private var active: AacExporter? = null

    override suspend fun export(
        wavFile: File,
        outFile: File,
        onProgress: ((done: Int, total: Int) -> Unit)?
    ): AacExportResult {
        val exporter = AacExporter()
        active = exporter
        try {
            return exporter.export(wavFile, outFile, onProgress)
        } finally {
            // Only clear it when this call is still the active one, so a cancel
            // that arrives for a newer export is never dropped.
            if (active === exporter) active = null
        }
    }

    override fun cancel() {
        active?.cancel()
    }
}
