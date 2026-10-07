package com.example.layanalyzer.media

import com.example.layanalyzer.data.VideoParamSets
import java.io.File

/**
 * RTP5-KT-02: the seam between `RtpViewModel` and RTP5-KT-01's muxer.
 *
 * It exists for the same reason `RtpNativeBridge` does for the repository: the
 * JVM unit tests of the view model must be able to see *that* the ES and its
 * index were handed to a muxer, with which codec/size/parameter sets and
 * towards which path -- and [RtpVideoMuxer] cannot run there at all, because it
 * is built on `MediaMuxer` and this module's `android.*` is a "not mocked" stub.
 * The signature is [RtpVideoMuxer.mux]'s, one for one.
 */
interface VideoMuxer {
    suspend fun mux(
        esFile: File,
        vidxFile: File,
        codec: String,
        width: Int,
        height: Int,
        paramSets: VideoParamSets,
        outFile: File,
        onProgress: ((done: Int, total: Int) -> Unit)? = null
    ): VideoMuxResult

    /** Asks a running [mux] to stop and clean up; a no-op when nothing is running. */
    fun cancel()
}

/**
 * The production [VideoMuxer]: a fresh [RtpVideoMuxer] per call.
 *
 * Fresh per call, not one shared instance, and that is not an optimisation
 * detail: [RtpVideoMuxer.cancel] latches its flag, so a shared muxer would let
 * one cancelled export poison every export after it with `cancelled`. The
 * instance an export is running on is remembered only so [cancel] has something
 * to reach -- the view model cancels through `cancelLongRunningOperations()`,
 * which stops the native export, and this is the remaining half that stops the
 * muxer's own sample loop.
 */
class PlatformVideoMuxer : VideoMuxer {

    @Volatile
    private var active: RtpVideoMuxer? = null

    override suspend fun mux(
        esFile: File,
        vidxFile: File,
        codec: String,
        width: Int,
        height: Int,
        paramSets: VideoParamSets,
        outFile: File,
        onProgress: ((done: Int, total: Int) -> Unit)?
    ): VideoMuxResult {
        val muxer = RtpVideoMuxer()
        active = muxer
        try {
            return muxer.mux(
                esFile, vidxFile, codec, width, height, paramSets, outFile, onProgress
            )
        } finally {
            // Only clear it when this call is still the active one, so a cancel
            // that arrives for a newer export is never dropped.
            if (active === muxer) active = null
        }
    }

    override fun cancel() {
        active?.cancel()
    }
}
