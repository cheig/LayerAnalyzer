// Copyright (c) 2026 cheig
// LayerAnalyzer - https://github.com/cheig/LayerAnalyzer
// Licensed under GNU GPL version 3; see LICENSE.

package com.example.layanalyzer.data

import android.media.MediaFormat
import android.util.Base64
import com.example.layanalyzer.NativeEngine
import com.example.layanalyzer.media.FidxFile
import com.example.layanalyzer.media.MediaCodecAudioDecoder
import com.example.layanalyzer.media.MediaCodecDecodeResult
import com.example.layanalyzer.model.RtpCodecCapabilities
import com.example.layanalyzer.model.RtpCodecCatalog
import com.example.layanalyzer.model.RtpCodecRoute
import com.example.layanalyzer.model.RtpCodecSource
import com.example.layanalyzer.model.RtpContainerExportResult
import com.example.layanalyzer.model.RtpDecodability
import com.example.layanalyzer.model.RtpDecodeRequest
import com.example.layanalyzer.model.RtpDecodeResult
import com.example.layanalyzer.model.RtpDecodeStats
import com.example.layanalyzer.model.RtpDecodedItem
import com.example.layanalyzer.model.RtpDtmfEvent
import com.example.layanalyzer.model.RtpEvent
import com.example.layanalyzer.model.RtpGap
import com.example.layanalyzer.model.RtpHeuristicResult
import com.example.layanalyzer.model.RtpMixResult
import com.example.layanalyzer.model.RtpOverrideResult
import com.example.layanalyzer.model.RtpPayloadOverride
import com.example.layanalyzer.model.RtpProgress
import com.example.layanalyzer.model.RtpRawExportResult
import com.example.layanalyzer.model.RtpRawOrder
import com.example.layanalyzer.model.RtpScanResult
import com.example.layanalyzer.model.RtpStream
import com.example.layanalyzer.model.RtpTimingMode
import com.example.layanalyzer.model.RtpUnsupportedReason
import com.example.layanalyzer.model.RtpUnsupportedStream
import com.example.layanalyzer.model.RtpVideoCodecData
import com.example.layanalyzer.model.RtpVideoExportResult
import kotlinx.coroutines.runBlocking
import org.json.JSONArray
import org.json.JSONObject
import java.io.File
import java.io.IOException
import java.util.Locale
import kotlin.coroutines.cancellation.CancellationException

/**
 * `RtpRepository` 与 JNI 之间的窄接缝（RTP4-KT-02）。
 *
 * 生产实现是 [NativeEngineBridge]，它只是 [NativeEngine] 的转发；单测注入自己的
 * 实现之后，「路由到 `UNSUPPORTED` 的编码一次 JNI 都没调」就成了可观测的断言，
 * 而不是「纯函数返回了 UNSUPPORTED」这种同义反复。接口只列 [RtpRepository] 真正
 * 会走的三个入口，JNI 声明仍然只有 `NativeEngine.kt` 一处（README §4.2）。
 */
internal interface RtpNativeBridge {
    fun decodeRtpAudio(
        sessionPtr: Long,
        requestJson: String,
        outDir: String,
        progress: NativeEngine.RtpProgressCallback?
    ): String

    fun extractRtpCodecFrames(
        sessionPtr: Long,
        requestJson: String,
        outDir: String,
        progress: NativeEngine.RtpProgressCallback?
    ): String

    fun renderRtpAudioFromPcm(
        sessionPtr: Long,
        requestJson: String,
        outDir: String
    ): String
}

/** [RtpNativeBridge] 的生产实现：逐个转发到 [NativeEngine]。 */
internal object NativeEngineBridge : RtpNativeBridge {
    override fun decodeRtpAudio(
        sessionPtr: Long,
        requestJson: String,
        outDir: String,
        progress: NativeEngine.RtpProgressCallback?
    ): String = NativeEngine.decodeRtpAudio(sessionPtr, requestJson, outDir, progress)

    override fun extractRtpCodecFrames(
        sessionPtr: Long,
        requestJson: String,
        outDir: String,
        progress: NativeEngine.RtpProgressCallback?
    ): String = NativeEngine.extractRtpCodecFrames(sessionPtr, requestJson, outDir, progress)

    override fun renderRtpAudioFromPcm(
        sessionPtr: Long,
        requestJson: String,
        outDir: String
    ): String = NativeEngine.renderRtpAudioFromPcm(sessionPtr, requestJson, outDir)
}

/**
 * RTP 流发现的 Kotlin 数据层（RTP1-KT-01）。
 *
 * 只负责封装 JNI 与解析 JSON；**不**缓存 session 句柄，每次调用都通过
 * [PacketRepository.currentSessionHandle] 现取（0 表示无会话，直接返回错误，不调用 JNI）。
 *
 * RTP4-KT-02 之后 [decodeAudio] 按编码路由：原生能解的走一次 `decodeRtpAudio`，
 * AMR / AMR-WB / Opus 走 `extractRtpCodecFrames` → `MediaCodecAudioDecoder` →
 * `renderRtpAudioFromPcm`，其余编码直接进 `unsupported`。两条路径对上层返回同一个
 * [RtpDecodeResult]。
 */
open class RtpRepository internal constructor(
    private val packetRepository: CaptureSessionDataSource,
    private val native: RtpNativeBridge
) {
    /** 生产构造入口；测试用 [RtpNativeBridge] 的 fake 走主构造函数。 */
    constructor(packetRepository: PacketRepository) :
        this(packetRepository, NativeEngineBridge)


    /**
     * 扫描当前会话的 RTP 流，返回 M1 契约（任务清单 §3.2）对应的 [RtpScanResult]。
     *
     * @param limitToDisplayFilter 为 true 时只扫描当前显示过滤器命中的帧
     * @param onProgress 进度回调；返回 false 表示取消
     */
    open fun scanRtpStreams(
        limitToDisplayFilter: Boolean = false,
        onProgress: ((RtpProgress) -> Boolean)? = null
    ): RtpScanResult {
        val sessionPtr = packetRepository.currentSessionHandle()
        if (sessionPtr == 0L) {
            return RtpScanResult(
                schemaVersion = SCHEMA_VERSION,
                error = "No capture is open.",
                cancelled = false,
                scanGeneration = 0L,
                framesScanned = 0L,
                heuristicEnabled = false,
                streamsTruncated = false,
                streams = emptyList()
            )
        }
        val requestJson = JSONObject()
            .put("limitToDisplayFilter", limitToDisplayFilter)
            .toString()
        val raw = NativeEngine.scanRtpStreams(
            sessionPtr,
            requestJson,
            NativeEngine.RtpProgressCallback { done, total ->
                onProgress?.invoke(RtpProgress(done, total)) ?: true
            }
        )
        return parseScanResult(raw)
    }

    /**
     * Decode selected RTP streams into WAV/peaks/map files (RTP2-NAT-06, routed
     * by RTP4-KT-02).
     *
     * 每个流按 [RtpCodecCatalog.route] 决定路径（卡片路由表）：
     *
     *  - `NATIVE`：交给原生的 `decodeRtpAudio`，一次调用解码全部这类流。
     *  - `MEDIACODEC`：`extractRtpCodecFrames` → [MediaCodecAudioDecoder] →
     *    `renderRtpAudioFromPcm`，逐流做，中间文件与最终 WAV 都写在 [outDir]
     *    这一个 request 目录里，取消或失败时整个目录一起删除。
     *  - `UNSUPPORTED`：不做任何解码，直接进结果的 `unsupported`；只要整单都是
     *    这一类，一次 JNI 都不调。
     *
     * 请求里没给出编码的流（`streamCodecs` 没有它）按 `NATIVE` 处理，与
     * RTP4-KT-02 之前完全一致。带 `mix` 的请求不做 MEDIACODEC 链：混音的两路
     * 必须先由调用方渲染成单声道 WAV，再用 `mix.leftWav`/`mix.rightWav` 交给原生
     * 混音（卡片第 4 条）。
     */
    open fun decodeAudio(
        request: RtpDecodeRequest,
        outDir: File,
        onProgress: ((RtpProgress) -> Boolean)? = null
    ): RtpDecodeResult {
        val sessionPtr = packetRepository.currentSessionHandle()
        if (sessionPtr == 0L) {
            return RtpDecodeResult(
                error = "No capture is open.",
                cancelled = false,
                items = emptyList(),
                unsupported = emptyList()
            )
        }

        val plan = planDecode(request)
        if (plan.isEmpty) {
            // 每个流都不可路由：一次 JNI 都不调，直接按契约回答。
            return RtpDecodeResult(
                error = "",
                cancelled = false,
                items = emptyList(),
                unsupported = plan.unsupported
            )
        }

        val steps = plan.nativeStreamIds.size + plan.mediaCodecStreamIds.size
        var doneWeight = 0
        val items = mutableListOf<RtpDecodedItem>()
        val unsupported = plan.unsupported.toMutableList()

        var failure: RtpDecodeResult? = null
        var mix: RtpMixResult? = null
        if (plan.nativeStreamIds.isNotEmpty()) {
            val slice = slicePercent(doneWeight, doneWeight + plan.nativeStreamIds.size, steps)
            doneWeight += plan.nativeStreamIds.size
            val parsed = parseDecodeResult(
                native.decodeRtpAudio(
                    sessionPtr,
                    buildDecodeRequest(request, plan.nativeStreamIds),
                    outDir.absolutePath,
                    NativeEngine.RtpProgressCallback(
                        SliceProgress(slice.first, slice.second, onProgress)::report
                    )
                )
            )
            items += parsed.items
            unsupported += parsed.unsupported
            // `mix` 只有原生路径会产出：带 `mix` 的请求整单都走原生（见 [planDecode]）。
            mix = parsed.mix
            failure = failedResult(parsed.error, parsed.cancelled, unsupported)
        }

        if (failure == null) {
            for (streamId in plan.mediaCodecStreamIds) {
                val slice = slicePercent(doneWeight, doneWeight + 1, steps)
                doneWeight += 1
                when (
                    val outcome = decodeMediaCodecStream(
                        sessionPtr, request, streamId, outDir,
                        slice.first, slice.second, onProgress
                    )
                ) {
                    is MediaCodecStreamDecode.Item -> items += outcome.item
                    is MediaCodecStreamDecode.Unsupported ->
                        unsupported += RtpUnsupportedStream(streamId, outcome.reason)

                    is MediaCodecStreamDecode.Failed ->
                        failure = failedResult(outcome.error, false, unsupported)

                    MediaCodecStreamDecode.Cancelled ->
                        failure = failedResult("", true, unsupported)
                }
                if (failure != null) {
                    // 卡片第 3 条：中间文件与最终 WAV 在同一个 request 目录，
                    // 取消/失败时按目录一起删除（RtpMediaCache 的口径）。
                    outDir.deleteRecursively()
                    break
                }
            }
        }

        return failure ?: RtpDecodeResult(
            error = "",
            cancelled = false,
            items = items.toList(),
            unsupported = unsupported.toList(),
            mix = mix
        )
    }

    /**
     * 取消/失败时的统一回答；没有失败就返回 null（这样调用方能直接连着用）。
     * `items` 留空：README §4.1 要求取消后不返回部分结果，原生路径在 error /
     * cancelled 时也把 `items` 留在初始的空数组上。
     */
    private fun failedResult(
        error: String,
        cancelled: Boolean,
        unsupported: List<RtpUnsupportedStream>
    ): RtpDecodeResult? =
        if (cancelled || error.isNotEmpty()) {
            RtpDecodeResult(
                error = error,
                cancelled = cancelled,
                items = emptyList(),
                unsupported = unsupported
            )
        } else {
            null
        }

    /** 一个流的解码路由划分（RTP4-KT-02 的卡片路由表）。 */
    private data class RtpDecodePlan(
        val nativeStreamIds: List<String>,
        val mediaCodecStreamIds: List<String>,
        val unsupported: List<RtpUnsupportedStream>
    ) {
        val isEmpty: Boolean
            get() = nativeStreamIds.isEmpty() && mediaCodecStreamIds.isEmpty()
    }

    /**
     * 按编码把请求里的流分成三类。
     *
     * `mix` 请求里 `MEDIACODEC` 的流也归到原生一侧：卡片第 4 条要求混音的两路先由
     * 调用方渲染成单声道 WAV 再传进来（`leftWav`/`rightWav`），所以这类请求不做
     * 三段提取；WAV 混音时原生层直接读那两个 WAV，不会去解码它们。
     */
    private fun planDecode(request: RtpDecodeRequest): RtpDecodePlan {
        val nativeIds = mutableListOf<String>()
        val mediaCodecIds = mutableListOf<String>()
        val unsupported = mutableListOf<RtpUnsupportedStream>()

        request.streamIds.forEach { streamId ->
            // 请求没描述这条流时按 NATIVE 走：RTP4-KT-02 之前每个调用方都是这个语义。
            val route = request.streamCodecs[streamId]
                ?.let(RtpCodecCatalog::route)
                ?: RtpCodecRoute.NATIVE
            when {
                route == RtpCodecRoute.UNSUPPORTED -> unsupported += RtpUnsupportedStream(
                    streamId = streamId,
                    reason = RtpUnsupportedReason.UNSUPPORTED.wireValue
                )

                request.mix != null || route == RtpCodecRoute.NATIVE -> nativeIds += streamId

                else -> mediaCodecIds += streamId
            }
        }
        return RtpDecodePlan(nativeIds, mediaCodecIds, unsupported)
    }

    /** [decodeMediaCodecStream] 的三种结果，外加取消。 */
    private sealed interface MediaCodecStreamDecode {
        data class Item(val item: RtpDecodedItem) : MediaCodecStreamDecode
        data class Unsupported(val reason: String) : MediaCodecStreamDecode
        data class Failed(val error: String) : MediaCodecStreamDecode
        data object Cancelled : MediaCodecStreamDecode
    }

    /**
     * `extractRtpCodecFrames` → [MediaCodecAudioDecoder] → `renderRtpAudioFromPcm`，
     * 全部落在 [outDir] 这一个 request 目录里（卡片第 3 条）：`<id>.frames`、
     * `<id>.fidx`、`<id>.pcmchunks` 和渲染出的 `<id>.wav`/`.peaks`/`.map` 同进同出。
     */
    private fun decodeMediaCodecStream(
        sessionPtr: Long,
        request: RtpDecodeRequest,
        streamId: String,
        outDir: File,
        fromPercent: Int,
        toPercent: Int,
        onProgress: ((RtpProgress) -> Boolean)?
    ): MediaCodecStreamDecode {
        val span = (toPercent - fromPercent).coerceAtLeast(0)
        fun sub(from: Int, to: Int) = SliceProgress(
            fromPercent + span * from / PROGRESS_SCALE,
            fromPercent + span * to / PROGRESS_SCALE,
            onProgress
        )
        val extractProgress = sub(0, EXTRACT_PERCENT)
        val decodeProgress = sub(EXTRACT_PERCENT, DECODE_PERCENT)
        val renderProgress = sub(DECODE_PERCENT, PROGRESS_SCALE)

        val extracted = runCatching {
            JSONObject(
                native.extractRtpCodecFrames(
                    sessionPtr,
                    buildCodecFramesRequest(request.scanGeneration, streamId),
                    outDir.absolutePath,
                    NativeEngine.RtpProgressCallback(extractProgress::report)
                )
            )
        }.getOrNull() ?: return MediaCodecStreamDecode.Failed(MALFORMED_FRAMES_RESPONSE)

        if (extracted.optBoolean("cancelled", false)) {
            return MediaCodecStreamDecode.Cancelled
        }
        val extractError = extracted.optString("error", "")
        if (extractError.isNotEmpty()) {
            // 原生层用短码回答「这条流不归我管 / 解不了」（nativeDecode、srtp、
            // needsMapping、staleScan、notFound），短码原样进 `unsupported`；
            // 其它错误（写文件失败等）才是真正的错误 —— 后者会整单失败，所以
            // 把「原生层想自己解码」也算成 unsupported 是对的：它没有坏，只是
            // 路由表和原生集合对不上（`nativeDecode` 没有对应的
            // `RtpUnsupportedReason` 常量，只在本卡的路由表里出现）。
            return if (extractError == NATIVE_DECODE_REASON ||
                RtpUnsupportedReason.fromWire(extractError) != null
            ) {
                MediaCodecStreamDecode.Unsupported(extractError)
            } else {
                MediaCodecStreamDecode.Failed(extractError)
            }
        }

        val framesPath = extracted.optString("framesPath", "")
        val indexPath = extracted.optString("indexPath", "")
        val mime = extracted.optString("mime", "")
        val sampleRate = extracted.optInt("sampleRate", 0)
        val channels = extracted.optInt("channels", 0)
        if (framesPath.isEmpty() || indexPath.isEmpty() || mime.isEmpty() ||
            sampleRate <= 0 || channels <= 0
        ) {
            return MediaCodecStreamDecode.Failed(MALFORMED_FRAMES_RESPONSE)
        }
        val csd = runCatching {
            extracted.optStringList("csd").map { Base64.decode(it, Base64.DEFAULT) }
        }.getOrNull() ?: return MediaCodecStreamDecode.Failed(MALFORMED_FRAMES_RESPONSE)

        val fidx = try {
            FidxFile.read(File(indexPath))
        } catch (error: IOException) {
            return MediaCodecStreamDecode.Failed(error.message ?: MALFORMED_FRAME_INDEX)
        }
        if (fidx.entries.isEmpty()) {
            return MediaCodecStreamDecode.Failed(MALFORMED_FRAME_INDEX)
        }

        val decoder = MediaCodecAudioDecoder()
        val pcmFile = File(outDir, "$streamId$PCM_CHUNKS_SUFFIX")
        val decoded = try {
            runBlocking {
                decoder.decode(
                    framesFile = File(framesPath),
                    fidx = fidx,
                    // 原生 mime → 平台 mime：AMR-NB 的原生契约是 "audio/amr"，而
                    // 平台把这个解码器登记为 "audio/3gpp"（卡片第 5 条）。
                    mime = platformAudioMime(mime),
                    sampleRate = sampleRate,
                    channels = channels,
                    csd = csd,
                    outFile = pcmFile,
                    onProgress = { done, total ->
                        if (!decodeProgress.report(done, total)) {
                            // 进度回调说停：让解码循环在下一个出队超时退出。
                            decoder.cancel()
                        }
                    }
                )
            }
        } catch (cancelled: CancellationException) {
            throw cancelled
        } catch (error: Exception) {
            return MediaCodecStreamDecode.Failed(error.message ?: MALFORMED_FRAMES_RESPONSE)
        }

        val ok = when (decoded) {
            is MediaCodecDecodeResult.Ok -> decoded
            is MediaCodecDecodeResult.Unsupported ->
                return MediaCodecStreamDecode.Unsupported(decoded.reason)

            is MediaCodecDecodeResult.Failed -> return if (
                decoded.message == MediaCodecAudioDecoder.CANCELLED
            ) {
                MediaCodecStreamDecode.Cancelled
            } else {
                MediaCodecStreamDecode.Failed(decoded.message)
            }
        }

        val rendered = runCatching {
            JSONObject(
                native.renderRtpAudioFromPcm(
                    sessionPtr,
                    buildPcmRenderRequest(
                        request = request,
                        streamId = streamId,
                        pcmPath = ok.pcmChunksPath,
                        sampleRate = ok.sampleRate,
                        channels = ok.channels
                    ),
                    outDir.absolutePath
                )
            )
        }.getOrNull() ?: return MediaCodecStreamDecode.Failed(MALFORMED_RENDER_RESPONSE)

        if (rendered.optBoolean("cancelled", false)) {
            return MediaCodecStreamDecode.Cancelled
        }
        val renderError = rendered.optString("error", "")
        if (renderError.isNotEmpty()) {
            return MediaCodecStreamDecode.Failed(renderError)
        }
        renderProgress.report(1, 1)
        return MediaCodecStreamDecode.Item(parseDecodedItem(rendered))
    }

    /** 原生 mime → 平台 mime（RTP4-KT-02 第 5 条），大小写不敏感。 */
    internal fun platformAudioMime(nativeMime: String): String =
        when (nativeMime.trim().lowercase(Locale.US)) {
            MIME_AMR_NATIVE -> MediaFormat.MIMETYPE_AUDIO_AMR_NB
            MIME_AMR_WB_NATIVE -> MediaFormat.MIMETYPE_AUDIO_AMR_WB
            MIME_OPUS_NATIVE -> MediaFormat.MIMETYPE_AUDIO_OPUS
            else -> nativeMime
        }

    /** `[fromWeight, toWeight)` 占 [steps] 步里的百分比区间。 */
    private fun slicePercent(fromWeight: Int, toWeight: Int, steps: Int): Pair<Int, Int> =
        Pair(
            fromWeight * PROGRESS_SCALE / steps,
            toWeight * PROGRESS_SCALE / steps
        )

    /**
     * 把一段子操作自己的 `0..total` 进度映射到整次请求的
     * `[startPercent, endPercent)` 上，并把回调的「继续吗」原样传出来。
     */
    private class SliceProgress(
        private val startPercent: Int,
        private val endPercent: Int,
        private val sink: ((RtpProgress) -> Boolean)?
    ) {
        fun report(done: Int, total: Int): Boolean {
            val callback = sink ?: return true
            val span = (endPercent - startPercent).coerceAtLeast(0)
            val value = if (total <= 0) {
                endPercent
            } else {
                startPercent + done.coerceIn(0, total) * span / total
            }
            return callback(RtpProgress(value, PROGRESS_SCALE))
        }
    }

    /** Export one stream's payload bytes in sequence or arrival order (RTP2-NAT-07). */
    open fun exportRaw(
        scanGeneration: Long,
        streamId: String,
        order: RtpRawOrder,
        outFile: File
    ): RtpRawExportResult {
        val sessionPtr = packetRepository.currentSessionHandle()
        if (sessionPtr == 0L) {
            return RtpRawExportResult(
                bytes = 0L,
                packets = 0L,
                error = "No capture is open."
            )
        }

        val raw = NativeEngine.exportRtpPayloadRaw(
            sessionPtr,
            buildRawExportRequest(scanGeneration, streamId, order),
            outFile.absolutePath
        )
        return parseRawExportResult(raw)
    }

    /**
     * Kept internal so the Kotlin/native request contract can be tested without JNI.
     *
     * [streamIds] 默认是请求里的全部流；[decodeAudio] 传入按路由筛过的子集
     * （`UNSUPPORTED` 的流不进原生请求，卡片第 3 条）。老调用方只用默认值。
     */
    internal fun buildDecodeRequest(
        request: RtpDecodeRequest,
        streamIds: List<String> = request.streamIds
    ): String {
        val json = JSONObject()
            .put("scanGeneration", request.scanGeneration)
            .put("streams", JSONArray(streamIds))
            .put("timing", request.timing.wireValue())
            .put("jitterMs", request.jitterMs)
        // RTP3-NAT-05：可选字段只在调用方给出时才出现，老调用方的请求形状不变。
        // `dtmf` 也只在 true 时写出（原生层缺省即 false），不额外发 `"dtmf": false`。
        request.mix?.let { mix ->
            val mixJson = JSONObject()
                .put("left", mix.leftStreamId)
                .put("right", mix.rightStreamId)
                .put("align", mix.align)
            // RTP4-KT-02：WAV 混音的输入与两路 peaks/map 同样只在给出时才写出，
            // 所以 RTP3-NAT-05 的请求形状一个字都没变。
            mixJson.putIfNotBlank("leftWav", mix.leftWav)
            mixJson.putIfNotBlank("rightWav", mix.rightWav)
            mixJson.putIfNotBlank("leftPeaks", mix.leftPeaks)
            mixJson.putIfNotBlank("leftMap", mix.leftMap)
            mixJson.putIfNotBlank("rightPeaks", mix.rightPeaks)
            mixJson.putIfNotBlank("rightMap", mix.rightMap)
            json.put("mix", mixJson)
        }
        if (request.dtmf) json.put("dtmf", true)
        return json.toString()
    }

    /**
     * `extractRtpCodecFrames` 的请求：只需要代次与流 id，打包模式留给原生层自动探测
     * （`amrMode` 缺省即 `auto`，见 RTP4-NAT-06 的契约）。
     *
     * Kept internal so the Kotlin/native request contract can be tested without JNI.
     */
    internal fun buildCodecFramesRequest(scanGeneration: Long, streamId: String): String =
        JSONObject()
            .put("scanGeneration", scanGeneration)
            .put("streamId", streamId)
            .toString()

    /**
     * `renderRtpAudioFromPcm` 的请求（RTP4-NAT-07）：采样率与声道数以 `MediaCodec`
     * 实际给出的为准（`MediaCodecDecodeResult.Ok`），时间轴参数沿用本次请求的。
     *
     * Kept internal so the Kotlin/native request contract can be tested without JNI.
     */
    internal fun buildPcmRenderRequest(
        request: RtpDecodeRequest,
        streamId: String,
        pcmPath: String,
        sampleRate: Int,
        channels: Int
    ): String =
        JSONObject()
            .put("scanGeneration", request.scanGeneration)
            .put("streamId", streamId)
            .put("pcmPath", pcmPath)
            .put("sampleRate", sampleRate)
            .put("channels", channels)
            .put("timing", request.timing.wireValue())
            .put("jitterMs", request.jitterMs)
            .toString()

    private fun JSONObject.putIfNotBlank(name: String, value: String): JSONObject =
        if (value.isBlank()) this else put(name, value)

    /** Kept internal so the Kotlin/native request contract can be tested without JNI. */
    internal fun buildRawExportRequest(
        scanGeneration: Long,
        streamId: String,
        order: RtpRawOrder
    ): String =
        JSONObject()
            .put("scanGeneration", scanGeneration)
            .put("streamId", streamId)
            .put("order", order.wireValue())
            .toString()

    /** Kept internal so the Kotlin/native JSON contract can be tested without JNI. */
    internal fun parseDecodeResult(json: String): RtpDecodeResult {
        val root = runCatching { JSONObject(json) }.getOrNull()
            ?: return malformedDecodeResult()
        return RtpDecodeResult(
            error = root.optString("error", ""),
            cancelled = root.optBoolean("cancelled", false),
            items = root.optObjectList("items").map(::parseDecodedItem),
            unsupported = root.optObjectList("unsupported").map { item ->
                RtpUnsupportedStream(
                    streamId = item.optString("streamId", ""),
                    reason = item.optString("reason", "")
                )
            },
            mix = root.optJSONObject("mix")?.let(::parseMixResult)
        )
    }

    /** Kept internal so the Kotlin/native JSON contract can be tested without JNI. */
    internal fun parseRawExportResult(json: String): RtpRawExportResult {
        val root = runCatching { JSONObject(json) }.getOrNull()
            ?: return RtpRawExportResult(
                bytes = 0L,
                packets = 0L,
                error = "Malformed RTP raw export response."
            )
        return RtpRawExportResult(
            bytes = root.optLong("bytes", 0L),
            packets = root.optLong("packets", 0L),
            error = root.optString("error", "")
        )
    }

    /**
     * Exports one AMR / AMR-WB / Opus stream as a native container file into [outDir]
     * (RTP4-NAT-06's `exportRtpContainer`, consumed by RTP4-KT-03).
     *
     * [format] 是原生的 `amr`/`awb`/`opus`，调用方必须按流自己的编码取
     * （`RtpCodecCatalog.containerFormat(codec)`）：原生侧会校验两者是否一致，不一致
     * 直接回 `error="format does not match the stream codec."`。原生能解的编码
     * （`g711A`/`g722`/`g729`/…）在这里回 `error="nativeDecode"`。
     *
     * `outDir` 只是被写入、不会被删除：与 `extractRtpCodecFrames` 的 per-request 目录
     * 不同，这个端点假定目录里还有别的东西，所以失败时只由原生层删掉半成品容器。
     *
     * 与 [exportRaw] 一样直接走 [NativeEngine]：`RtpNativeBridge` 是 RTP4-KT-02 为
     * 「按路由分派」开的那道缝，导出端点不属于它。
     */
    open fun exportContainer(
        scanGeneration: Long,
        streamId: String,
        format: String,
        outDir: File
    ): RtpContainerExportResult {
        val sessionPtr = packetRepository.currentSessionHandle()
        if (sessionPtr == 0L) {
            return RtpContainerExportResult(
                path = "",
                format = format,
                frameCount = 0L,
                byteCount = 0L,
                error = "No capture is open."
            )
        }

        val raw = NativeEngine.exportRtpContainer(
            sessionPtr,
            buildContainerExportRequest(scanGeneration, streamId, format),
            outDir.absolutePath
        )
        return parseContainerExportResult(raw)
    }

    /**
     * Kept internal so the Kotlin/native request contract can be tested without JNI.
     *
     * `format` 只在调用方给出时写出，缺省由原生层按 `format must be amr, awb or opus.`
     * 拒绝（fail-closed，不猜）。
     */
    internal fun buildContainerExportRequest(
        scanGeneration: Long,
        streamId: String,
        format: String
    ): String =
        JSONObject()
            .put("scanGeneration", scanGeneration)
            .put("streamId", streamId)
            .put("format", format)
            .toString()

    /** Kept internal so the Kotlin/native JSON contract can be tested without JNI. */
    internal fun parseContainerExportResult(json: String): RtpContainerExportResult {
        val root = runCatching { JSONObject(json) }.getOrNull()
            ?: return RtpContainerExportResult(
                path = "",
                format = "",
                frameCount = 0L,
                byteCount = 0L,
                error = "Malformed RTP container export response."
            )
        return RtpContainerExportResult(
            path = root.optString("path", ""),
            format = root.optString("format", ""),
            frameCount = root.optLong("frameCount", 0L),
            byteCount = root.optLong("byteCount", 0L),
            error = root.optString("error", ""),
            cancelled = root.optBoolean("cancelled", false)
        )
    }

    /**
     * Exports one H.264 / H.265 stream as an Annex-B elementary stream plus its
     * `.vidx` access-unit index (RTP5-NAT-05), the two files RTP5-KT-01's muxer
     * wraps in an MP4.
     *
     * 与 [exportRaw] / [exportContainer] 一样直接走 [NativeEngine]：`RtpNativeBridge`
     * 是 RTP4-KT-02 为「按路由分派」开的那道缝，导出端点不属于它。
     *
     * **可选字段今天谁也给不出。** 请求里 `paramSets` / `tsRate` / `donDiff` /
     * `paramSetsPresentInStream` 都是可选的，缺省时原生层按「调用方不知道」处理
     * （用流自己的时钟、不注入参数集、不在带内找）。给它们赋值的唯一来源是 SDP fmtp，
     * 而 RTP3-NAT-04 的 `readRtpSetupInfo` **在本仓库还不存在**（本文件之外也只有
     * 两处 TODO 指向它），所以没有任何调用方能填 [paramSets]；`RtpViewModel` 的
     * 视频导出缺省就传 null。缺了它原生层只能看带内参数集：流里有 SPS 时宽高照常
     * 解析；带内也没有时整个请求回「缺少参数集（SDP 与带内均未找到）」且**不写文件**。
     * 不要为了填这个字段去读 SDP、更不要凭空造参数集（README §4.5.4）。
     *
     * @param codec 规范 ID `H264` / `H265`；与流的编码不一致时原生层直接回
     *   `error="codec does not match the stream."`
     * @param outDir 两个产物的输出目录；取消和失败时由原生层整个删掉（调用方应当给
     *   本次导出一个自己的目录）
     * @param onProgress 进度回调，`done`/`total` 是百分数（`total == 100`）。返回 false
     *   会让原生层停下并回 `cancelled=true`。大文件的遍历要几分钟，
     *   [com.example.layanalyzer.viewmodel.RtpViewModel] 把这个数画成进度条。
     */
    open fun exportVideo(
        scanGeneration: Long,
        streamId: String,
        codec: String,
        startAtKeyframe: Boolean,
        dropCorrupt: Boolean,
        outDir: File,
        paramSets: VideoParamSets? = null,
        tsRate: Int? = null,
        donDiff: Int? = null,
        paramSetsPresentInStream: Boolean? = null,
        onProgress: ((RtpProgress) -> Boolean)? = null
    ): RtpVideoExportResult {
        val sessionPtr = packetRepository.currentSessionHandle()
        if (sessionPtr == 0L) {
            return RtpVideoExportResult(error = "No capture is open.")
        }

        val raw = NativeEngine.exportRtpVideo(
            sessionPtr,
            buildVideoExportRequest(
                scanGeneration = scanGeneration,
                streamId = streamId,
                codec = codec,
                startAtKeyframe = startAtKeyframe,
                dropCorrupt = dropCorrupt,
                paramSets = paramSets,
                tsRate = tsRate,
                donDiff = donDiff,
                paramSetsPresentInStream = paramSetsPresentInStream
            ),
            outDir.absolutePath,
            onProgress?.let { callback ->
                NativeEngine.RtpProgressCallback { done, total ->
                    callback(RtpProgress(done, total))
                }
            }
        )
        return parseVideoExportResult(raw)
    }

    /**
     * Kept internal so the Kotlin/native request contract can be tested without JNI.
     *
     * 五个必填键（`scanGeneration` / `streamId` / `codec` / `startAtKeyframe` /
     * `dropCorrupt`）永远写出；四个可选字段**只在调用方真的给了值**时才出现。
     * 这不是省字节：原生层对 `tsRate` 用 `has_ts_rate` 区分「调用方说了 90000」与
     * 「没说，用流自己的时钟」，对 `paramSetsPresentInStream` 缺省是 false 而显式
     * `false` 是「KT-00 断言过带内没有」——补一个默认值就把这两件事合成一件了。
     *
     * 空的 [paramSets]（三个列表里没有一个非空项）与 `null` 一样不写出这个键：
     * 原生 `parse_video_param_sets` 把空数组当「没有」，写出去只是噪声；反过来，
     * 一旦要写出，其成员**必须**是非空 Base64 —— 空串或非法 Base64 会让原生层
     * 拒绝整个请求，而不是忽略那一项。
     */
    internal fun buildVideoExportRequest(
        scanGeneration: Long,
        streamId: String,
        codec: String,
        startAtKeyframe: Boolean,
        dropCorrupt: Boolean,
        paramSets: VideoParamSets? = null,
        tsRate: Int? = null,
        donDiff: Int? = null,
        paramSetsPresentInStream: Boolean? = null,
        encode: (ByteArray) -> String = ::androidBase64Encode
    ): String {
        val json = JSONObject()
            .put("scanGeneration", scanGeneration)
            .put("streamId", streamId)
            .put("codec", codec)
            .put("startAtKeyframe", startAtKeyframe)
            .put("dropCorrupt", dropCorrupt)
        paramSets?.takeIf { it.hasAnyParameterSet() }?.let { sets ->
            json.put(
                "paramSets",
                JSONObject()
                    .put("sps", JSONArray(sets.sps.map(encode)))
                    .put("pps", JSONArray(sets.pps.map(encode)))
                    .put("vps", JSONArray(sets.vps.map(encode)))
            )
        }
        tsRate?.let { json.put("tsRate", it) }
        donDiff?.let { json.put("donDiff", it) }
        paramSetsPresentInStream?.let { json.put("paramSetsPresentInStream", it) }
        return json.toString()
    }

    /**
     * Kept internal so the Kotlin/native JSON contract can be tested without JNI.
     *
     * 容忍原生**预置结果**的每一个键：`csd` 恒存在且三个值是 `null`、
     * `unsupportedNalCounts` 恒有契约里的四个键（值为 0）、`firstKeyframeIndex`
     * 缺省 -1。`JSONObject.NULL` 不能走 `optString`（`JSONObject.NULL.toString()` 是
     * 字符串 `"null"`），所以 `csd` 的三项显式判 `isNull`。
     */
    internal fun parseVideoExportResult(json: String): RtpVideoExportResult {
        val root = runCatching { JSONObject(json) }.getOrNull()
            ?: return RtpVideoExportResult(
                error = "Malformed RTP video export response."
            )
        return RtpVideoExportResult(
            schemaVersion = root.optInt("schemaVersion", 0),
            error = root.optString("error", ""),
            cancelled = root.optBoolean("cancelled", false),
            esPath = root.optString("esPath", ""),
            indexPath = root.optString("indexPath", ""),
            codec = root.optString("codec", ""),
            width = root.optInt("width", 0),
            height = root.optInt("height", 0),
            profile = root.optString("profile", ""),
            level = root.optString("level", ""),
            csd = parseVideoCodecData(root.optJSONObject("csd")),
            frames = root.optLong("frames", 0L),
            keyframes = root.optLong("keyframes", 0L),
            corruptFrames = root.optLong("corruptFrames", 0L),
            firstKeyframeIndex = root.optLong("firstKeyframeIndex", -1L),
            durationMs = root.optLong("durationMs", 0L),
            fpsEstimate = root.optDouble("fpsEstimate", 0.0),
            unsupportedNalCounts = root.optLongMap("unsupportedNalCounts"),
            widthSource = root.optString("widthSource", "")
        )
    }

    /** `csd` 的三个 Base64 值；缺键与 `null` 都是「没有这一组」。 */
    private fun parseVideoCodecData(node: JSONObject?): RtpVideoCodecData {
        if (node == null) return RtpVideoCodecData.EMPTY
        return RtpVideoCodecData(
            sps = node.stringOrNull("sps"),
            pps = node.stringOrNull("pps"),
            vps = node.stringOrNull("vps")
        )
    }

    private fun JSONObject.stringOrNull(name: String): String? =
        if (isNull(name)) null else optString(name, "").ifEmpty { null }

    /**
     * `unsupportedNalCounts` 是名字 → 包数。契约里的四个键之外还会有原生追加的
     * 包型名（`type31`、`AP(DONL)`、`reserved` 之类，NAT-05 decision 14），它们
     * **都要收下**：UI-01 的摘要显示的就是这张表的全部内容。
     */
    private fun JSONObject.optLongMap(name: String): Map<String, Long> {
        val node = optJSONObject(name) ?: return emptyMap()
        val out = LinkedHashMap<String, Long>()
        for (key in node.keys()) {
            out[key] = node.optLong(key, 0L)
        }
        return out
    }

    /** 打开/关闭 `rtp_udp` 族启发式（进程级设置，不需要会话）。 */
    fun setRtpHeuristicEnabled(enabled: Boolean): RtpHeuristicResult {
        val raw = NativeEngine.setRtpHeuristicEnabled(enabled)
        val root = runCatching { JSONObject(raw) }.getOrNull()
            ?: return RtpHeuristicResult(enabled = enabled, error = "Malformed RTP heuristic response.")
        return RtpHeuristicResult(
            enabled = root.optBoolean("enabled", enabled),
            error = root.optString("error", "")
        )
    }

    fun isRtpHeuristicEnabled(): Boolean = NativeEngine.isRtpHeuristicEnabled()

    /**
     * 本构建的编码能力（RTP4-KT-05）：`getRtpCodecCapabilities()` 的解析结果。
     *
     * 与 [setRtpHeuristicEnabled] / [isRtpHeuristicEnabled] 一样**不**走
     * [RtpNativeBridge]：那道缝是 RTP4-KT-02 为「按路由分派」开的（见
     * [exportContainer] 的说明），能力查询不属于它。进程级、无会话，所以不需要
     * `sessionPtr`，未打开文件时也能回答。
     *
     * **fail-open**：JNI 抛异常或回答解析不了时返回
     * [RtpCodecCapabilities.UNKNOWN]，而不是把「什么都不知道」表达成「什么都不可用」。
     * 调用方（PT 映射对话框）据此一条都不置灰 —— 卡片 §2.5 明确要求拿不到列表时
     * 不要把整个对话框锁死。
     */
    open fun codecCapabilities(): RtpCodecCapabilities {
        val raw = try {
            NativeEngine.getRtpCodecCapabilities()
        } catch (e: Exception) {
            return RtpCodecCapabilities.UNKNOWN
        }
        return parseCodecCapabilities(raw)
    }

    /**
     * Kept internal so the Native/Kotlin JSON contract can be tested without JNI
     * (RTP4-KT-05). 缺失/畸形的字段一律按 [RtpCodecCapabilities.UNKNOWN] 的口径
     * 兜底（容忍未知字段与缺失字段，README §4.2）：`g729`/`ilbc` 缺失当作 true，
     * 两个列表缺失当作空集。
     */
    internal fun parseCodecCapabilities(json: String): RtpCodecCapabilities {
        val root = try {
            JSONObject(json)
        } catch (e: Exception) {
            return RtpCodecCapabilities.UNKNOWN
        }
        return RtpCodecCapabilities(
            audio = root.optStringList("audio").toSet(),
            video = root.optStringList("video").toSet(),
            g729 = root.optBoolean("g729", true),
            ilbc = root.optBoolean("ilbc", true)
        )
    }

    /** 整体替换会话级动态 PT 覆盖表（fail-closed：任一非法项由原生层拒绝）。 */
    open fun setRtpPayloadOverrides(overrides: List<RtpPayloadOverride>): RtpOverrideResult {
        val sessionPtr = packetRepository.currentSessionHandle()
        if (sessionPtr == 0L) {
            return RtpOverrideResult(error = "No capture is open.", count = 0)
        }
        val requestJson = buildOverridesRequest(overrides)
        val raw = NativeEngine.setRtpPayloadOverrides(sessionPtr, requestJson)
        val root = runCatching { JSONObject(raw) }.getOrNull()
            ?: return RtpOverrideResult(error = "Malformed RTP override response.", count = 0)
        return RtpOverrideResult(
            error = root.optString("error", ""),
            count = root.optInt("count", 0)
        )
    }

    /**
     * 把覆盖表组装成原生契约的请求 JSON：`{"overrides":[{"pt":..,"codec":..,"clockRate":..,"channels":..}]}`。
     * 字符串一律交给 [JSONObject] 转义，不手工拼串。
     *
     * Kept internal so the Kotlin/native JSON contract can be tested without JNI (RTP1-KT-04).
     */
    internal fun buildOverridesRequest(overrides: List<RtpPayloadOverride>): String {
        val items = JSONArray()
        overrides.forEach { override ->
            items.put(
                JSONObject()
                    .put("pt", override.pt)
                    .put("codec", override.codec)
                    .put("clockRate", override.clockRate)
                    .put("channels", override.channels)
            )
        }
        return JSONObject().put("overrides", items).toString()
    }

    /** Kept internal so the Native/Kotlin JSON contract can be tested without JNI. */
    internal fun parseScanResult(json: String): RtpScanResult {
        val root = runCatching { JSONObject(json) }.getOrNull() ?: return malformedScanResult()
        val streamsJson = root.optJSONArray("streams")
        val streams = buildList {
            if (streamsJson != null) {
                for (index in 0 until streamsJson.length()) {
                    val item = streamsJson.optJSONObject(index) ?: continue
                    add(parseStream(item))
                }
            }
        }
        return RtpScanResult(
            schemaVersion = root.optInt("schemaVersion", 0),
            error = root.optString("error", ""),
            cancelled = root.optBoolean("cancelled", false),
            scanGeneration = root.optLong("scanGeneration", 0L),
            framesScanned = root.optLong("framesScanned", 0L),
            heuristicEnabled = root.optBoolean("heuristicEnabled", false),
            streamsTruncated = root.optBoolean("streamsTruncated", false),
            streams = streams
        )
    }

    private fun parseDecodedItem(item: JSONObject): RtpDecodedItem {
        val stats = item.optJSONObject("stats")
        return RtpDecodedItem(
            streamId = item.optString("streamId", ""),
            codec = item.optString("codec", ""),
            sampleRate = item.optInt("sampleRate", 0),
            channels = item.optInt("channels", 0),
            wavPath = item.optString("wavPath", ""),
            peaksPath = item.optString("peaksPath", ""),
            mapPath = item.optString("mapPath", ""),
            durationMs = item.optLong("durationMs", 0L),
            startRel = item.optDouble("startRel", 0.0),
            startAbsEpochMs = item.optLong("startAbsEpochMs", 0L),
            gaps = item.optObjectList("gaps").map { gap ->
                RtpGap(
                    atMs = gap.optLong("atMs", 0L),
                    durMs = gap.optLong("durMs", 0L),
                    reason = gap.optString("reason", ""),
                    clipped = gap.optBoolean("clipped", false),
                    frame = gap.optLong("frame", 0L)
                )
            },
            events = item.optObjectList("events").map { event ->
                RtpEvent(
                    atMs = event.optLong("atMs", 0L),
                    type = event.optString("type", ""),
                    value = event.optString("value", ""),
                    frame = event.optLong("frame", 0L)
                )
            },
            stats = RtpDecodeStats(
                decodedPackets = stats?.optLong("decodedPackets", 0L) ?: 0L,
                droppedLate = stats?.optLong("droppedLate", 0L) ?: 0L,
                lost = stats?.optLong("lost", 0L) ?: 0L,
                truncatedPackets = stats?.optLong("truncatedPackets", 0L) ?: 0L,
                zeroPayloadPackets = stats?.optLong("zeroPayloadPackets", 0L) ?: 0L
            ),
            // RTP3-NAT-05：老版本原生层不返回 `dtmf`，缺失时就是空列表。
            dtmf = item.optObjectList("dtmf").map { event ->
                RtpDtmfEvent(
                    digit = event.optString("digit", ""),
                    atMs = event.optLong("atMs", 0L),
                    durMs = event.optLong("durMs", 0L),
                    volume = event.optInt("volume", 0),
                    frame = event.optLong("frame", 0L)
                )
            }
        )
    }

    /** RTP3-NAT-05 的 `mix` 对象；字段缺失时按 0/空串兜底，保证老原生层也能解析。 */
    private fun parseMixResult(mix: JSONObject): RtpMixResult = RtpMixResult(
        wavPath = mix.optString("wavPath", ""),
        channels = mix.optInt("channels", 0),
        sampleRate = mix.optInt("sampleRate", 0),
        durationMs = mix.optLong("durationMs", 0L),
        leftOffsetMs = mix.optLong("leftOffsetMs", 0L),
        rightOffsetMs = mix.optLong("rightOffsetMs", 0L),
        resampled = mix.optBoolean("resampled", false),
        peaksLeftPath = mix.optString("peaksLeftPath", ""),
        peaksRightPath = mix.optString("peaksRightPath", ""),
        mapLeftPath = mix.optString("mapLeftPath", ""),
        mapRightPath = mix.optString("mapRightPath", "")
    )

    private fun parseStream(item: JSONObject): RtpStream = RtpStream(
        id = item.optString("id", ""),
        src = item.optString("src", ""),
        srcPort = item.optInt("srcPort", 0),
        dst = item.optString("dst", ""),
        dstPort = item.optInt("dstPort", 0),
        ssrc = item.optLong("ssrc", 0L),
        ssrcHex = item.optString("ssrcHex", ""),
        pt = item.optInt("pt", 0),
        codec = item.optString("codec", ""),
        codecSource = parseCodecSource(item.optString("codecSource", "")),
        clockRate = item.optInt("clockRate", 0),
        setupFrame = item.optLong("setupFrame", 0L),
        setupMethod = item.optString("setupMethod", ""),
        isSrtp = item.optBoolean("isSrtp", false),
        packets = item.optLong("packets", 0L),
        expected = item.optLong("expected", 0L),
        lost = item.optLong("lost", 0L),
        lostPct = item.optDouble("lostPct", 0.0),
        seqErrors = item.optLong("seqErrors", 0L),
        outOfOrder = item.optLong("outOfOrder", 0L),
        truncated = item.optLong("truncated", 0L),
        problem = item.optBoolean("problem", false),
        minDeltaMs = item.optDouble("minDeltaMs", 0.0),
        meanDeltaMs = item.optDouble("meanDeltaMs", 0.0),
        maxDeltaMs = item.optDouble("maxDeltaMs", 0.0),
        maxDeltaFrame = item.optLong("maxDeltaFrame", 0L),
        minJitterMs = item.optNullableDouble("minJitterMs"),
        meanJitterMs = item.optNullableDouble("meanJitterMs"),
        maxJitterMs = item.optNullableDouble("maxJitterMs"),
        jitterAvailable = item.optBoolean("jitterAvailable", false),
        maxSkewMs = item.optDouble("maxSkewMs", 0.0),
        bytes = item.optLong("bytes", 0L),
        firstFrame = item.optLong("firstFrame", 0L),
        lastFrame = item.optLong("lastFrame", 0L),
        startRel = item.optDouble("startRel", 0.0),
        endRel = item.optDouble("endRel", 0.0),
        firstAbsEpochUs = item.optLong("firstAbsEpochUs", 0L),
        ptsSeen = item.optIntList("ptsSeen"),
        decodable = parseDecodability(item.optString("decodable", "")),
        decodableReason = item.optString("decodableReason", ""),
        primaryPayloadType = item.optInt("primaryPayloadType", 0)
    )

    private fun parseCodecSource(raw: String): RtpCodecSource = when (raw) {
        "static" -> RtpCodecSource.STATIC
        "sdp" -> RtpCodecSource.SDP
        "override" -> RtpCodecSource.OVERRIDE
        else -> RtpCodecSource.UNKNOWN
    }

    private fun parseDecodability(raw: String): RtpDecodability = when (raw) {
        "yes" -> RtpDecodability.YES
        "needsMapping" -> RtpDecodability.NEEDS_MAPPING
        "srtp" -> RtpDecodability.SRTP
        "truncated" -> RtpDecodability.TRUNCATED
        else -> RtpDecodability.UNSUPPORTED
    }

    private fun malformedScanResult(): RtpScanResult = RtpScanResult(
        schemaVersion = SCHEMA_VERSION,
        error = "Malformed RTP scan response.",
        cancelled = false,
        scanGeneration = 0L,
        framesScanned = 0L,
        heuristicEnabled = false,
        streamsTruncated = false,
        streams = emptyList()
    )

    private fun malformedDecodeResult(): RtpDecodeResult = RtpDecodeResult(
        error = "Malformed RTP decode response.",
        cancelled = false,
        items = emptyList(),
        unsupported = emptyList()
    )

    private fun JSONObject.optNullableDouble(name: String): Double? =
        if (isNull(name) || !has(name)) null else optDouble(name)

    private fun JSONObject.optIntList(name: String): List<Int> {
        val array = optJSONArray(name) ?: return emptyList()
        return buildList {
            for (index in 0 until array.length()) add(array.optInt(index, 0))
        }
    }

    private fun JSONObject.optStringList(name: String): List<String> {
        val array = optJSONArray(name) ?: return emptyList()
        return buildList {
            for (index in 0 until array.length()) {
                val value = array.optString(index, "")
                if (value.isNotEmpty()) add(value)
            }
        }
    }

    private fun JSONObject.optObjectList(name: String): List<JSONObject> {
        val array = optJSONArray(name) ?: return emptyList()
        return buildList {
            for (index in 0 until array.length()) {
                array.optJSONObject(index)?.let(::add)
            }
        }
    }

    private fun RtpTimingMode.wireValue(): String = when (this) {
        RtpTimingMode.JITTER -> "jitter"
        RtpTimingMode.RTP_TIMESTAMP -> "rtp"
        RtpTimingMode.UNINTERRUPTED -> "uninterrupted"
    }

    private fun RtpRawOrder.wireValue(): String = when (this) {
        RtpRawOrder.SEQ -> "seq"
        RtpRawOrder.ARRIVAL -> "arrival"
    }

    private companion object {
        const val SCHEMA_VERSION = 1

        /** 进度一律按 0..100 报，与原生 `decodeRtpAudio` 的口径一致。 */
        const val PROGRESS_SCALE = 100

        /** 提取 / 解码 / 渲染在一条流的进度区间里各占多少（卡片没有规定，取经验值）。 */
        const val EXTRACT_PERCENT = 30
        const val DECODE_PERCENT = 90

        /** `MediaCodecAudioDecoder` 的输出扩展名；`.fidx` 由原生层按同目录推出。 */
        const val PCM_CHUNKS_SUFFIX = ".pcmchunks"

        /** 原生 `extractRtpCodecFrames` 报告的 mime（NAT-06 冻结的契约，KT-02 不改）。 */
        const val MIME_AMR_NATIVE = "audio/amr"
        const val MIME_AMR_WB_NATIVE = "audio/amr-wb"
        const val MIME_OPUS_NATIVE = "audio/opus"

        const val MALFORMED_FRAMES_RESPONSE = "Malformed RTP codec frame response."
        const val MALFORMED_FRAME_INDEX = "Malformed RTP frame index."
        const val MALFORMED_RENDER_RESPONSE = "Malformed RTP PCM render response."

        /**
         * `extractRtpCodecFrames` 对原生能解的编码回的错误短码（RTP4-NAT-06 的契约，
         * 也是 KT-02 路由表与原生集合必须一致的那条规则的另一种说法）。
         */
        const val NATIVE_DECODE_REASON = "nativeDecode"
    }
}

/**
 * RTP5-KT-02：这组参数集里至少有一个非空项。
 *
 * 口径与 `SdpVideoParams.ParseResult.hasParameterSets` 一致（`sps` / `pps` / `vps`
 * 各看有没有非空项）。三个列表全空与「根本没有 SDP 参数集」对原生层是同一件事，
 * 所以 [RtpRepository.buildVideoExportRequest] 对两者都不写出 `paramSets` 键。
 */
internal fun VideoParamSets.hasAnyParameterSet(): Boolean =
    sps.any { it.isNotEmpty() } || pps.any { it.isNotEmpty() } || vps.any { it.isNotEmpty() }

/**
 * 生产环境的 Base64 编码，`NO_WRAP` 让结果是一行（SDP 的 `sprop-parameter-sets`
 * 就是这个形状，原生层的 `base64_decode` 两样都收）。
 *
 * **不要在 JVM 单测的执行路径上走到这里**：本模块的 `android.*` 是 not mocked 的桩。
 * `buildVideoExportRequest` 因此留了一个 `encode` 参数（默认就是本函数）供单测注入
 * `java.util.Base64` —— 与 `data/SdpVideoParams.kt` 的解码接缝（RTP5-KT-00）是同一个
 * 做法，只是方向相反。
 */
private fun androidBase64Encode(bytes: ByteArray): String =
    Base64.encodeToString(bytes, Base64.NO_WRAP)
