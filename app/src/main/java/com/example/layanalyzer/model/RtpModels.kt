// Copyright (c) 2026 cheig
// LayerAnalyzer - https://github.com/cheig/LayerAnalyzer
// Licensed under GNU GPL version 3; see LICENSE.

package com.example.layanalyzer.model

import java.util.Locale

/**
 * RTP 流发现的数据模型（RTP1-KT-01）。
 *
 * 字段与 JNI 契约一一对应，见 NativeEngine.kt。
 */
data class RtpStream(
    val id: String, val src: String, val srcPort: Int, val dst: String, val dstPort: Int,
    val ssrc: Long, val ssrcHex: String,
    val pt: Int, val codec: String, val codecSource: RtpCodecSource, val clockRate: Int,
    val setupFrame: Long, val setupMethod: String, val isSrtp: Boolean,
    val packets: Long, val expected: Long, val lost: Long, val lostPct: Double,
    val seqErrors: Long, val outOfOrder: Long, val truncated: Long, val problem: Boolean,
    val minDeltaMs: Double, val meanDeltaMs: Double, val maxDeltaMs: Double, val maxDeltaFrame: Long,
    val minJitterMs: Double?, val meanJitterMs: Double?, val maxJitterMs: Double?, val jitterAvailable: Boolean,
    val maxSkewMs: Double, val bytes: Long,
    val firstFrame: Long, val lastFrame: Long, val startRel: Double, val endRel: Double,
    val firstAbsEpochUs: Long,
    val ptsSeen: List<Int>, val decodable: RtpDecodability, val decodableReason: String,
    val primaryPayloadType: Int
)

data class RtpScanResult(
    val schemaVersion: Int, val error: String, val cancelled: Boolean,
    val scanGeneration: Long, val framesScanned: Long, val heuristicEnabled: Boolean,
    val streamsTruncated: Boolean, val streams: List<RtpStream>
) { val isSuccess: Boolean get() = error.isEmpty() && !cancelled }

enum class RtpDecodability { YES, NEEDS_MAPPING, SRTP, UNSUPPORTED, TRUNCATED }

enum class RtpCodecSource { STATIC, SDP, OVERRIDE, UNKNOWN }

data class RtpPayloadOverride(val pt: Int, val codec: String, val clockRate: Int, val channels: Int)

data class RtpProgress(val done: Int, val total: Int)

/**
 * `setRtpHeuristicEnabled` 的返回值，对应原生 JSON `{"enabled": <bool>, "error": "<msg>"}`。
 */
data class RtpHeuristicResult(
    val enabled: Boolean,
    val error: String
) { val isSuccess: Boolean get() = error.isEmpty() }

/**
 * `setRtpPayloadOverrides` 的返回值，对应原生 JSON `{"error": "<msg>", "count": <n>}`。
 */
data class RtpOverrideResult(
    val error: String,
    val count: Int
) { val isSuccess: Boolean get() = error.isEmpty() }

/**
 * The five-tuple + SSRC identity needed to navigate from a dissected RTP packet
 * back to one row in the stream list (RTP1-UI-03).
 */
data class RtpStreamIdentity(
    val src: String,
    val srcPort: Int,
    val dst: String,
    val dstPort: Int,
    val ssrc: Long
) {
    fun matches(stream: RtpStream): Boolean =
        src == stream.src && srcPort == stream.srcPort &&
            dst == stream.dst && dstPort == stream.dstPort && ssrc == stream.ssrc

    companion object {
        /** Extracts the identity from `ProtocolNode.filterValue` fields, if complete. */
        fun fromProtocolTree(root: ProtocolNode?): RtpStreamIdentity? {
            if (root == null) return null
            val values = linkedMapOf<String, String>()
            fun visit(node: ProtocolNode) {
                val field = node.filter?.trim()?.lowercase()
                val value = node.filterValue?.trim()?.removeSurrounding("\"")
                if (!field.isNullOrEmpty() && !value.isNullOrEmpty()) {
                    values.putIfAbsent(field, value)
                }
                node.children.forEach(::visit)
            }
            visit(root)

            val src = values["ip.src"] ?: values["ipv6.src"] ?: return null
            val dst = values["ip.dst"] ?: values["ipv6.dst"] ?: return null
            val srcPort = values["udp.srcport"]?.toIntOrNull() ?: return null
            val dstPort = values["udp.dstport"]?.toIntOrNull() ?: return null
            val ssrc = values["rtp.ssrc"]?.let { raw ->
                runCatching {
                    if (raw.startsWith("0x", ignoreCase = true)) java.lang.Long.decode(raw) else raw.toLong()
                }.getOrNull()
            } ?: return null
            return RtpStreamIdentity(src, srcPort, dst, dstPort, ssrc)
        }
    }
}

/**
 * `mix.align` 的唯一取值（RTP3-NAT-05）：两路按各自首包的绝对到达时间对齐。
 *
 * 原生解析器只接受这一个值，其它取值一律 fail-closed。
 */
const val RTP_MIX_ALIGN_ABS_ARRIVAL = "absArrival"

/**
 * `decodeRtpAudio` 的立体声混音请求（RTP3-NAT-05）：左声道 [leftStreamId]、
 * 右声道 [rightStreamId]。
 *
 * 两个流 id **必须同时出现在** [RtpDecodeRequest.streamIds] 里，否则原生层会拒绝整个请求；
 * 调用方也需要 `items` 里那两条流各自的单声道 WAV。
 *
 * RTP4-KT-02 追加了六个可选字段，它们只服务「两路已经由调用方渲染成 WAV」这一种
 * 混音（卡片第 4 条：MEDIACODEC 的编码先各自渲染成单声道 WAV，再交给原生混音）：
 * [leftWav]/[rightWav] 同时非空时，原生层**跳过提取与解码**，直接把这两个 WAV 当
 * PCM 走 `mix_stereo`；[leftPeaks]/[leftMap]/[rightPeaks]/[rightMap] 是调用方已经
 * 渲染好的那两路 peaks/map，原样回填进 [RtpMixResult] 的四个路径字段（缺失时是空串）。
 *
 * 只给出其中一个 WAV 会被原生层拒绝，不做猜测。
 */
data class RtpMixRequest(
    val leftStreamId: String,
    val rightStreamId: String,
    val align: String = RTP_MIX_ALIGN_ABS_ARRIVAL,
    val leftWav: String = "",
    val rightWav: String = "",
    val leftPeaks: String = "",
    val leftMap: String = "",
    val rightPeaks: String = "",
    val rightMap: String = ""
)

/** RTP2-KT-01: Kotlin request model for `decodeRtpAudio`. */
data class RtpDecodeRequest(
    val scanGeneration: Long,
    val streamIds: List<String>,
    val timing: RtpTimingMode,
    val jitterMs: Int = 50,
    /** RTP3-NAT-05：给定时原生层额外产出立体声 `mix.wav`；`null` 时只渲染单声道。 */
    val mix: RtpMixRequest? = null,
    /** RTP3-NAT-05：为带 telephone-event 的流解析 RFC 4733 DTMF 事件。 */
    val dtmf: Boolean = false,
    /**
     * RTP4-KT-02：流 id → 规范编码 ID（`RtpStream.codec`），`RtpRepository.decodeAudio`
     * 用它查 [RtpCodecCatalog.route] 来决定每个流走哪条解码路径（卡片路由表）。
     *
     * 表里没有的流按 [RtpCodecRoute.NATIVE] 处理：这正是 RTP4-KT-02 之前每个调用方
     * 的语义，所以老调用方（只填 [streamIds]）的行为一个字都没变。
     */
    val streamCodecs: Map<String, String> = emptyMap()
)

enum class RtpTimingMode { JITTER, RTP_TIMESTAMP, UNINTERRUPTED }

data class RtpGap(
    val atMs: Long,
    val durMs: Long,
    val reason: String,
    val clipped: Boolean,
    val frame: Long
)

data class RtpEvent(
    val atMs: Long,
    val type: String,
    val value: String,
    val frame: Long
)

data class RtpDecodedItem(
    val streamId: String,
    val codec: String,
    val sampleRate: Int,
    val channels: Int,
    val wavPath: String,
    val peaksPath: String,
    val mapPath: String,
    val durationMs: Long,
    val startRel: Double,
    val startAbsEpochMs: Long,
    val gaps: List<RtpGap>,
    val events: List<RtpEvent>,
    val stats: RtpDecodeStats,
    /**
     * RTP3-NAT-05：该流的 RFC 4733 DTMF 事件（按到达顺序）。
     *
     * 只有请求里 `dtmf=true` 且该流有 telephone-event 负载类型时才非空；老版本原生层
     * 不返回这个字段，解析后就是空列表。
     */
    val dtmf: List<RtpDtmfEvent> = emptyList()
)

/**
 * 一个 RFC 4733 DTMF 事件（RTP3-NAT-05，数字映射与时长口径见 `DtmfParser`）。
 *
 * @param digit `0`–`9` / `*` / `#` / `A`–`D`，表外的 event id 为 `event:<n>`。
 * @param atMs 事件第一个包在输出时间轴上的位置（毫秒）。
 * @param durMs 事件时长（毫秒），取最后一个包的 duration 字段换算。
 * @param volume 事件包的音量字段（6 位）。
 * @param frame 事件第一个包的帧号，用于「跳到数据包」。
 */
data class RtpDtmfEvent(
    val digit: String,
    val atMs: Long,
    val durMs: Long,
    val volume: Int,
    val frame: Long
)

data class RtpDecodeStats(
    val decodedPackets: Long,
    val droppedLate: Long,
    val lost: Long,
    val truncatedPackets: Long,
    val zeroPayloadPackets: Long
)

data class RtpUnsupportedStream(
    val streamId: String,
    val reason: String
)

/** Native `unsupported[].reason` values used by the RTP player. */
enum class RtpUnsupportedReason(val wireValue: String) {
    SRTP("srtp"),
    NEEDS_MAPPING("needsMapping"),
    UNSUPPORTED("unsupported"),
    STALE_SCAN("staleScan"),
    NOT_FOUND("notFound");

    companion object {
        fun fromWire(value: String): RtpUnsupportedReason? =
            entries.firstOrNull { it.wireValue.equals(value.trim(), ignoreCase = true) }
    }
}

/**
 * `decodeRtpAudio` 的立体声混音结果（RTP3-NAT-05）。
 *
 * 两路的采样率不同时，原生层用线性插值把较低的一路升到较高者并置 [resampled]
 * （与 Wireshark 的差异点，见 `RtpAudioRenderer`）。[peaksLeftPath] / [mapLeftPath]
 * 等四路指向 `items` 里同一批单声道文件，方便播放器直接按轨道取用。
 */
data class RtpMixResult(
    val wavPath: String,
    val channels: Int,
    val sampleRate: Int,
    val durationMs: Long,
    val leftOffsetMs: Long,
    val rightOffsetMs: Long,
    val resampled: Boolean,
    val peaksLeftPath: String,
    val peaksRightPath: String,
    val mapLeftPath: String,
    val mapRightPath: String
)

data class RtpDecodeResult(
    val error: String,
    val cancelled: Boolean,
    val items: List<RtpDecodedItem>,
    val unsupported: List<RtpUnsupportedStream>,
    /** RTP3-NAT-05：只有请求里带 `mix` 且原生层成功混音时才非空。 */
    val mix: RtpMixResult? = null
) {
    val isSuccess: Boolean get() = error.isEmpty() && !cancelled
}

enum class RtpRawOrder { SEQ, ARRIVAL }

data class RtpRawExportResult(
    val bytes: Long,
    val packets: Long,
    val error: String
) {
    val isSuccess: Boolean get() = error.isEmpty()
}

/**
 * `exportRtpContainer` 的返回值（RTP4-NAT-06 冻结的契约，RTP4-KT-03 消费）。
 *
 * 对应原生 JSON
 * `{"path":".../s3.amr","format":"amr","frameCount":1500,"byteCount":45600}`；
 * 失败时 `error` 非空、`path` 为空串，且原生层已经删掉半成品容器。
 */
data class RtpContainerExportResult(
    val path: String,
    val format: String,
    val frameCount: Long,
    val byteCount: Long,
    val error: String,
    val cancelled: Boolean = false
) {
    val isSuccess: Boolean get() = error.isEmpty() && !cancelled
}

/**
 * `exportRtpVideo` 的返回值（RTP5-NAT-05 冻结的 `task_rtp_m5_video.md` §3.1 契约，
 * RTP5-KT-02 消费）。
 *
 * 字段与原生 JSON 一一对应。**原生把每个键都用中性值预置好了**
 * （`RtpJni.cpp` 的 `Java_.._exportRtpVideo`），所以失败时拿到的也是同一个形状：
 * `esPath`/`indexPath` 为空串、`frames` 等为 0、`firstKeyframeIndex` 为 -1、
 * `csd` 是三个 `null`。解析器必须容忍这套预置值（见 [RtpRepository.parseVideoExportResult]）。
 *
 * [widthSource] 只在**读不出宽高**时才由原生带上（NAT-05 decision 11），取值 `unknown`；
 * 键缺失即「宽高是真的」。别把它当「宽高的来源」去猜别的取值 —— 今天它只有这一个值。
 *
 * [unsupportedNalCounts] 是包型名 → 包数：契约里固定四个键（`STAP-B`/`MTAP16`/`FU-B`/
 * `PACI`）在预置结果里就存在且为 0，原生只**追加**它真的数到的那些类型（decision 14），
 * 所以这个映射里可能出现契约之外的键（例如 `type31`、`AP(DONL)`），解析一律照收。
 */
data class RtpVideoExportResult(
    val schemaVersion: Int = 0,
    val error: String = "",
    val cancelled: Boolean = false,
    val esPath: String = "",
    val indexPath: String = "",
    val codec: String = "",
    val width: Int = 0,
    val height: Int = 0,
    val profile: String = "",
    val level: String = "",
    val csd: RtpVideoCodecData = RtpVideoCodecData.EMPTY,
    val frames: Long = 0L,
    val keyframes: Long = 0L,
    val corruptFrames: Long = 0L,
    val firstKeyframeIndex: Long = -1L,
    val durationMs: Long = 0L,
    val fpsEstimate: Double = 0.0,
    val unsupportedNalCounts: Map<String, Long> = emptyMap(),
    val widthSource: String = ""
) {
    val isSuccess: Boolean get() = error.isEmpty() && !cancelled

    /**
     * 两个产物路径都非空。`isSuccess` 还不够：预置结果（成功形状但什么都没写）也满足
     * `isSuccess`，调用方按它去 `File("")` 只会得到一个空路径，所以真要动文件之前
     * 还得过这一关。
     */
    val hasFiles: Boolean get() = esPath.isNotBlank() && indexPath.isNotBlank()

    /**
     * 宽高是不是从 SPS 真读出来的：既要有正的宽高，也不能是原生标注的 `unknown`。
     * 0 与 `unknown` 都是「不知道」，调用方（RTP5-KT-01 的封装器）对两者都走
     * 1280x720 的回退。
     */
    val widthKnown: Boolean
        get() = width > 0 && height > 0 &&
            !widthSource.equals(WIDTH_SOURCE_UNKNOWN, ignoreCase = true)

    /** `unsupportedNalCounts` 的总包数；UI-01 的摘要显示的就是它。 */
    val unsupportedNalPackets: Long get() = unsupportedNalCounts.values.sum()

    companion object {
        /** 原生在「SPS 读不出宽高」时放进 [widthSource] 的唯一取值。 */
        const val WIDTH_SOURCE_UNKNOWN = "unknown"
    }
}

/**
 * `exportRtpVideo` 结果里的 `csd`：写出的 ES 开头带的那组参数集，Base64（不含起始码）。
 *
 * 没有的项是 `null`，预置结果里三项全是 `null`。它是**生产方**对「我刚写的文件里带的是
 * 哪组参数集」的权威回答（RTP5-NAT-05 decision 7/10），与它据以算出 `width`/`height` 的
 * 是同一组字节 —— 所以它是 KT-01 封装器那条 `csd-0`/`csd-1` 的第二个来源
 * （`data/VideoTrackParamSets.kt` 的 [videoTrackParamSets]），**当且仅当**调用方拿不出
 * SDP 的参数集时使用（RTP3-NAT-04 的 `readRtpSetupInfo` 今天还不存在，所以那时它常常
 * 是唯一的来源）。
 *
 * 它与 `VideoParamSets`（RTP5-KT-00）不是同一件事，别混：后者装的是 **SDP** 声明的值，
 * 在 `exportRtpVideo` 的**请求**里是「这条流自己缺参数集时注入到流开头」用的；这里装的
 * 是**结果**，即写出的 ES 里实际有的那组。
 */
data class RtpVideoCodecData(
    val sps: String? = null,
    val pps: String? = null,
    val vps: String? = null
) {
    val isEmpty: Boolean get() = sps == null && pps == null && vps == null

    companion object {
        val EMPTY = RtpVideoCodecData()
    }
}

/**
 * 视频流的两种导出产物（RTP5-KT-02）。
 *
 * **为什么不在 [RtpExportFormat] 上加两个取值。** 那张表是音频目录的表：
 * `RtpCodecCatalog.exportFormats` 按它取值、`RtpExportKind.of(format)` 按它反查，
 * 而视频的 MIME 不是「一种格式一个常量」—— 裸流的 MIME 由**编码**决定
 * （`.h264` → `video/h264`、`.h265` → `video/hevc`，见 [rtpVideoRawMimeType]），
 * MP4 才是固定的一种。往音频表里塞视频取值，`RtpExportKind.of` 与 `exportFormats`
 * 都要开始处理「这个格式对这条流不适用」，换来的只是一个枚举名。
 *
 * 两种格式的产物路径也不是一处来的：MP4 是 KT-01 的 `RtpVideoMuxer` 写的，
 * 裸流是原生 `exportRtpVideo` 直接写的。
 */
enum class RtpVideoExportFormat {
    /** KT-01 的封装产物（`.mp4`，外部打开用 `video/mp4`）。 */
    MP4,

    /** 原生直接写出的 Annex-B 裸流（`.h264` / `.h265`）。 */
    RAW
}

/**
 * 一次「设备能不能解这个视频编码」的查询结论（RTP5-KT-02）。
 *
 * [UNKNOWN] 是「查询本身失败」（平台抛异常），不是「没有」：两者必须分开，否则一次
 * 查询失败会变成一句吓人的提示。
 */
enum class RtpVideoDecoderAvailability {
    /** 平台报告有该编码的解码器。 */
    AVAILABLE,

    /** 平台报告没有该编码的解码器：卡片要求给提示，但**仍然允许导出**。 */
    MISSING,

    /** 查询不了（平台异常、探针不可用）：不提示，也不拦导出（fail-open）。 */
    UNKNOWN;

    /**
     * 卡片原文：「H.265 在设备没有 HEVC 解码器时给出提示，但**仍然允许导出**」。
     * 三个取值都不拦导出路径 —— 这条规则就是本枚举要钉住的唯一行为约束。
     */
    val exportAllowed: Boolean get() = true

    /** 只有确认「没有解码器」才提示；[AVAILABLE] 与 [UNKNOWN] 都不打扰用户。 */
    val noticeRequired: Boolean get() = this == MISSING
}

/**
 * 探针的布尔答案 → [RtpVideoDecoderAvailability]。
 *
 * 纯函数：`android.media.*` 的那一次调用在 `media/VideoDecoderProbe.kt` 里
 * （`MediaCodecList.findDecoderForFormat`），本模块的 JVM 单测碰不了它。
 */
fun rtpVideoDecoderAvailability(decoderFound: Boolean?): RtpVideoDecoderAvailability =
    when (decoderFound) {
        null -> RtpVideoDecoderAvailability.UNKNOWN
        true -> RtpVideoDecoderAvailability.AVAILABLE
        false -> RtpVideoDecoderAvailability.MISSING
    }

/**
 * RTP5-KT-03：「应用内预览」这个入口到底能不能给。
 *
 * 卡片要的是「未实现时 UI 不显示该入口（而不是显示灰色按钮）」，也就是说 UI-01 需要一个
 * **可以据以隐藏**的信号，而不是一个还要它自己去追问「为什么」的布尔值。所以这里不是
 * `Boolean`，而是把三种情形分开，每一种都是一个不同的决定：
 *
 *  - [NoExport]：盘上没有可预览的 MP4（或它的 `.vidx` 不在）—— 隐藏入口。
 *  - [UnsupportedCodec]：文件在，**但这台设备没有这个编码的解码器** —— 与「没有文件」是
 *    两回事，把它报成 [NoExport] 会把一个设备能力问题说成导出问题。UI-01 可以据此隐藏，
 *    也可以照 KT-02 的口径给一句提示。
 *  - [Ready]：可以播。
 */
sealed interface RtpVideoPreviewAvailability {
    /** 没有可预览的 MP4（KT-01 的产物或它的 `.vidx` 不在）。 */
    data object NoExport : RtpVideoPreviewAvailability

    /** MP4 在，但本机解不开 [codec]（规范 ID）。 */
    data class UnsupportedCodec(val codec: String) : RtpVideoPreviewAvailability

    /** MP4 与索引都在，可以预览。 */
    data class Ready(
        val mp4Path: String,
        val indexPath: String
    ) : RtpVideoPreviewAvailability
}

/**
 * 预览可用性的纯决策（RTP5-KT-03）。
 *
 * 顺序是刻意的，**先看文件再看解码器**：没有文件时绝对不能因为顺手拿到的解码器答案是
 * 「没有」就报成 [RtpVideoPreviewAvailability.UnsupportedCodec] —— 那会把「没导出」说成
 * 「设备不行」。「这台设备解不开」只有在前两个条件都成立之后才可能成立。
 *
 * [decoderAvailable] 为 `null` 表示**查询本身失败**（与 KT-02 的
 * [RtpVideoDecoderAvailability.UNKNOWN] 同一口径）：这时判 [RtpVideoPreviewAvailability.Ready]，
 * fail-open —— 查不出来不等于没有，不能因为一次查询异常就把功能藏起来。
 *
 * [filesPresent] 由调用方查盘得出（本函数不碰文件系统，才能单测）；[codec] 是规范 ID，
 * 不是视频编码时判 [RtpVideoPreviewAvailability.NoExport]。
 *
 * **不做缓存包含检查**：`isCacheFile` 那一套（`RtpViewModel.exportVideoSource`）是给**写**
 * 用的，管的是「导出落点必须在 RTP 媒体缓存里」。预览只读，路径来自本仓库自己的导出结果，
 * 多一道包含检查只会多出一个「缓存没配置 ⇒ 不能预览」的失败模式。
 */
fun rtpVideoPreviewAvailability(
    mp4Path: String,
    indexPath: String,
    filesPresent: Boolean,
    codec: String?,
    decoderAvailable: Boolean?
): RtpVideoPreviewAvailability = when {
    !filesPresent || mp4Path.isBlank() || indexPath.isBlank() ->
        RtpVideoPreviewAvailability.NoExport

    codec == null -> RtpVideoPreviewAvailability.NoExport
    decoderAvailable == false -> RtpVideoPreviewAvailability.UnsupportedCodec(codec)
    else -> RtpVideoPreviewAvailability.Ready(mp4Path, indexPath)
}

/** Sanitizes one component of an RTP export file name. */
fun sanitizeRtpFileNameComponent(value: String): String {
    val sanitized = buildString(value.length) {
        value.forEach { character ->
            append(
                if (
                    character.isWhitespace() ||
                    Character.isSpaceChar(character) ||
                    character in RTP_FILE_NAME_ILLEGAL_CHARACTERS
                ) {
                    '_'
                } else {
                    character
                }
            )
        }
    }
    return sanitized.ifBlank { "_" }
}

/** Returns `rtp_<src>_<srcPort>-<dst>_<dstPort>_<ssrcHex>.wav`. */
fun rtpWavFileName(stream: RtpStream): String =
    "${rtpExportFileStem(stream)}.wav"

/**
 * Returns the raw payload extension for a codec the raw export supports, or null.
 *
 * RTP4-KT-03 补齐了卡片「编码 → 可用格式」表里的裸流家族（G.722 / G.726-* /
 * AAL2-G726-* / G.729）：原生的 `exportRtpPayloadRaw` 只写主 PT 的负载字节，本来
 * 就不限编码，缺的只是这里的后缀命名。表与管线必须一致，否则格式菜单会给出一个
 * 按下去必然失败的按钮。
 */
fun rtpRawExtension(codec: String): String? = when (codec.lowercase(Locale.US)) {
    "g711a", "pcma" -> "pcma"
    "g711u", "pcmu" -> "pcmu"
    "l16" -> "l16"
    "g722" -> "g722"
    "g729", "g729a", "g729b" -> "g729"
    "g726-16", "g726-24", "g726-32", "g726-40" -> codec.lowercase(Locale.US)
    "aal2-g726-16", "aal2-g726-24", "aal2-g726-32", "aal2-g726-40" ->
        codec.lowercase(Locale.US)

    else -> null
}

/** Returns the raw payload file name, or null for an unsupported codec. */
fun rtpRawFileName(stream: RtpStream): String? =
    rtpRawExtension(stream.codec)?.let { extension ->
        "${rtpExportFileStem(stream)}.$extension"
    }

/**
 * RTP4-KT-03：容器格式的导出文件名（`rtp_<src>_<srcPort>-<dst>_<dstPort>_<ssrc>.<ext>`），
 * 与 [rtpWavFileName] / [rtpRawFileName] 同一形状。
 *
 * 与 [rtpRawFileName] 一样**看编码**：格式与流不匹配（例如拿 AMR 去命名一条 G.711A
 * 的流）时返回 null，调用方就不会写出一个后缀与内容不符的文件。判定口径是
 * [RtpCodecCatalog.exportFormats]，与导出管线和格式菜单同一张表。
 */
fun rtpContainerFileName(stream: RtpStream, format: RtpExportFormat): String? =
    format.extension
        ?.takeIf { format.isContainer && format in RtpCodecCatalog.exportFormats(stream.codec) }
        ?.let { extension -> "${rtpExportFileStem(stream)}.$extension" }

/**
 * RTP4-KT-03：一种导出格式在这条流上的文件名；该格式不成立时返回 null
 * （`WAV` 恒有名字，`RAW`/容器看编码，见 [rtpRawFileName] / [rtpContainerFileName]）。
 */
fun rtpExportFileName(stream: RtpStream, format: RtpExportFormat): String? = when (format) {
    RtpExportFormat.WAV -> rtpWavFileName(stream)
    RtpExportFormat.RAW -> rtpRawFileName(stream)
    RtpExportFormat.AMR, RtpExportFormat.AWB, RtpExportFormat.OPUS ->
        rtpContainerFileName(stream, format)
}

/**
 * 裸流文件的 MIME（卡片固定的两个值）。
 *
 * **与 `VideoMuxFormat.MIME_H264` 不是同一样东西**：那个是 `MediaFormat` 给轨道用的
 * `video/avc`（`MediaExtractor` 读回来也是它），这里是交给外部应用去**打开一个文件**
 * 的 MIME，卡片写的就是 `video/h264`。H.265 的 `video/hevc` 两个用途恰好同值，但
 * 常量各归各的层。`application/octet-stream` 的回退不在这里，见 ViewModel 的
 * `videoOpenMimeTypes`（卡片第 1 条只给裸流要回退）。
 */
const val MIME_VIDEO_H264 = "video/h264"

/** 裸流文件的 MIME（`.h265`），见 [MIME_VIDEO_H264] 的说明。 */
const val MIME_VIDEO_HEVC = "video/hevc"

/**
 * RTP5-KT-02：流的编码 → `exportRtpVideo` 请求里的 `codec`（原生只认 `H264` / `H265`，
 * 别的取值会把整个请求判成 `codec must be H264 or H265.`）；不是这两种编码时返回 null。
 *
 * 与 [rtpRawExtension] 同一口径：只认 README §4.3 的规范 ID（大小写不敏感），
 * `HEVC` 这类别名不在这里展开 —— 流上的 `codec` 早就被原生 `RtpCodecNames::canonical()`
 * 归一化成规范 ID 了（C13），`PS` 也要先由调用方解析出真正的编码（KT-01 的
 * `VideoMuxFormat.mimeFor` 对 `PS` 同样回 null，两边一致）。
 */
fun rtpVideoCodecId(codec: String): String? = when (codec.trim().lowercase(Locale.US)) {
    "h264" -> "H264"
    "h265" -> "H265"
    else -> null
}

/**
 * 裸流的文件后缀（`h264` / `h265`），不是这两种编码时 null。
 *
 * 与 [rtpRawExtension] 同形状：后缀由编码决定，所以 [RtpVideoExportFormat] 里没有
 * 一个固定的 extension 字段可抄。
 */
fun rtpVideoRawExtension(codec: String): String? =
    rtpVideoCodecId(codec)?.lowercase(Locale.US)

/** 裸流文件打开时用的 MIME（`video/h264` / `video/hevc`），不是视频编码时 null。 */
fun rtpVideoRawMimeType(codec: String): String? = when (rtpVideoCodecId(codec)) {
    "H264" -> MIME_VIDEO_H264
    "H265" -> MIME_VIDEO_HEVC
    else -> null
}

/**
 * RTP5-KT-02 的裸流文件名（`rtp_<src>_<srcPort>-<dst>_<dstPort>_<ssrc>.h264`），
 * 与 [rtpRawFileName] 同一形状、同一个词干（卡片：「文件名规则与 M2 相同」）。
 *
 * 会**看编码**：不是 H.264/H.265 时返回 null，调用方就不会写出一个后缀与内容不符的文件。
 */
fun rtpVideoRawFileName(stream: RtpStream): String? =
    rtpVideoRawExtension(stream.codec)?.let { extension ->
        "${rtpExportFileStem(stream)}.$extension"
    }

/** MP4 的导出文件名；不是 H.264/H.265 时 null（理由同 [rtpVideoRawFileName]）。 */
fun rtpVideoMp4FileName(stream: RtpStream): String? =
    rtpVideoCodecId(stream.codec)?.let { "${rtpExportFileStem(stream)}.mp4" }

/**
 * 一种视频导出格式在这条流上的文件名；该格式不成立（不是视频编码）时返回 null。
 *
 * 与 [rtpExportFileName] 对应，但**不能**合并成一个函数：那条分支按 [RtpExportFormat]
 * 取值，而视频格式不在那张表里（见 [RtpVideoExportFormat] 的说明）。
 */
fun rtpVideoFileName(stream: RtpStream, format: RtpVideoExportFormat): String? = when (format) {
    RtpVideoExportFormat.MP4 -> rtpVideoMp4FileName(stream)
    RtpVideoExportFormat.RAW -> rtpVideoRawFileName(stream)
}

private fun rtpExportFileStem(stream: RtpStream): String {
    val source = sanitizeRtpFileNameComponent(stream.src)
    val destination = sanitizeRtpFileNameComponent(stream.dst)
    val ssrc = sanitizeRtpFileNameComponent(
        stream.ssrcHex.ifBlank { "0x%08x".format(stream.ssrc and 0xffffffffL) }
    )
    return "rtp_${source}_${stream.srcPort}-${destination}_${stream.dstPort}_$ssrc"
}

private val RTP_FILE_NAME_ILLEGAL_CHARACTERS = setOf('/', '\\', ':', '*', '?', '"', '<', '>', '|')
