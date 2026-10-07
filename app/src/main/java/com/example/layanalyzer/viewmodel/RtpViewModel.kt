// Copyright (c) 2026 cheig
// LayerAnalyzer - https://github.com/cheig/LayerAnalyzer
// Licensed under GNU GPL version 3; see LICENSE.

package com.example.layanalyzer.viewmodel

import android.view.Surface
import androidx.lifecycle.ViewModel
import androidx.lifecycle.viewModelScope
import com.example.layanalyzer.data.CaptureSessionCoordinator
import com.example.layanalyzer.data.RtpMediaCache
import com.example.layanalyzer.data.RtpRepository
import com.example.layanalyzer.data.VideoParamSets
import com.example.layanalyzer.data.videoTrackParamSets
import com.example.layanalyzer.data.VoipCall
import com.example.layanalyzer.media.AacEncoderProbe
import com.example.layanalyzer.media.AacExportResult
import com.example.layanalyzer.media.AacTrackExporter
import com.example.layanalyzer.media.AudioVideoMuxer
import com.example.layanalyzer.media.AvMuxResult
import com.example.layanalyzer.media.ExternalPlayerLauncher
import com.example.layanalyzer.media.PlatformAacEncoderProbe
import com.example.layanalyzer.media.PlatformAacTrackExporter
import com.example.layanalyzer.media.PlatformAudioVideoMuxer
import com.example.layanalyzer.media.PlatformVideoDecoderProbe
import com.example.layanalyzer.media.PlatformVideoMuxer
import com.example.layanalyzer.media.RtpAudioPlayerController
import com.example.layanalyzer.media.RtpAvMuxAvailability
import com.example.layanalyzer.media.RtpPlayerState
import com.example.layanalyzer.media.RtpVideoPreviewController
import com.example.layanalyzer.media.VideoDecoderProbe
import com.example.layanalyzer.media.VideoMuxResult
import com.example.layanalyzer.media.VideoMuxer
import com.example.layanalyzer.media.VideoMuxFormat
import com.example.layanalyzer.media.VidxEntry
import com.example.layanalyzer.media.VidxFile
import com.example.layanalyzer.media.isCorrupt
import com.example.layanalyzer.media.linkedCallFor
import com.example.layanalyzer.media.primaryAudioStream
import com.example.layanalyzer.media.rtpAvMuxAvailability
import com.example.layanalyzer.model.ExportResult
import com.example.layanalyzer.model.RtpCodecCatalog
import com.example.layanalyzer.model.RtpDecodability
import com.example.layanalyzer.model.RtpDecodeRequest
import com.example.layanalyzer.model.RtpDecodeResult
import com.example.layanalyzer.model.RtpDecodedItem
import com.example.layanalyzer.model.RtpExportFormat
import com.example.layanalyzer.model.RtpPayloadOverride
import com.example.layanalyzer.model.RtpProgress
import com.example.layanalyzer.model.RtpRawOrder
import com.example.layanalyzer.model.RtpScanResult
import com.example.layanalyzer.model.RtpStream
import com.example.layanalyzer.model.RtpTimingMode
import com.example.layanalyzer.model.RtpUnsupportedStream
import com.example.layanalyzer.model.RtpVideoDecoderAvailability
import com.example.layanalyzer.model.RtpVideoExportFormat
import com.example.layanalyzer.model.RtpVideoExportResult
import com.example.layanalyzer.model.RtpVideoPreviewAvailability
import com.example.layanalyzer.model.rtpContainerFileName
import com.example.layanalyzer.model.rtpRawFileName
import com.example.layanalyzer.model.rtpVideoCodecId
import com.example.layanalyzer.model.rtpVideoDecoderAvailability
import com.example.layanalyzer.model.rtpVideoFileName
import com.example.layanalyzer.model.rtpVideoMp4FileName
import com.example.layanalyzer.model.rtpVideoPreviewAvailability
import com.example.layanalyzer.model.rtpVideoRawMimeType
import com.example.layanalyzer.model.rtpWavFileName
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.CoroutineDispatcher
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.CoroutineStart
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.delay
import kotlinx.coroutines.Job
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.flow.collect
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import java.io.File

/** RTP 流发现页面的状态（RTP1-KT-02）。[Idle] 是初始状态。 */
sealed interface RtpScanUiState {
    data object Idle : RtpScanUiState
    data class Running(val done: Int, val total: Int) : RtpScanUiState
    data class Done(val result: RtpScanResult) : RtpScanUiState
    data class Error(val message: String) : RtpScanUiState
    data object Cancelled : RtpScanUiState
}

enum class RtpPlayerDecodeStatus {
    IDLE,
    DECODING,
    READY,
    ERROR,
    CANCELLED
}

/**
 * RTP player session state.
 *
 * [streams] and [decodedItems] are lists so RTP2-UI-03 can add stream tabs
 * without changing the ViewModel contract; RTP2-UI-02 opens one stream.
 */
data class RtpPlayerUiState(
    val streams: List<RtpStream> = emptyList(),
    val selectedStreamId: String? = null,
    val timing: RtpTimingMode = RtpTimingMode.JITTER,
    val status: RtpPlayerDecodeStatus = RtpPlayerDecodeStatus.IDLE,
    val progress: RtpProgress? = null,
    val decodedItems: List<RtpDecodedItem> = emptyList(),
    val unsupported: List<RtpUnsupportedStream> = emptyList(),
    val errorMessage: String? = null
) {
    val isOpen: Boolean
        get() = selectedStreamId != null

    val selectedStream: RtpStream?
        get() = streams.firstOrNull { it.id == selectedStreamId }

    val selectedItem: RtpDecodedItem?
        get() = decodedItems.firstOrNull { it.streamId == selectedStreamId }
}

/** One SAF destination supplied by the UI. [write] runs on the IO dispatcher. */
data class RtpExportDestination(
    val displayName: String,
    val write: (File) -> Unit
)

/**
 * 一次导出的种类（RTP2-KT-04，RTP4-KT-03 补齐容器格式）。
 *
 * 每个取值都挂着它对应的 [RtpExportFormat]：格式表住在 `RtpCodecCatalog`（卡片点名），
 * 这里只是把「菜单里选的格式」变成 [performExport] 能穷尽枚举的种类。WAV 与裸流
 * 的取值必须留给既有调用方（`exportWav`/`exportRaw`/`shareWav`/`shareRaw` 的签名与
 * 行为都没变）。
 */
enum class RtpExportKind(val format: RtpExportFormat) {
    WAV(RtpExportFormat.WAV),
    RAW(RtpExportFormat.RAW),
    AMR(RtpExportFormat.AMR),
    AWB(RtpExportFormat.AWB),
    OPUS(RtpExportFormat.OPUS);

    companion object {
        /** [RtpExportFormat] → [RtpExportKind]，供导出格式对话框（RTP4-KT-03）使用。 */
        fun of(format: RtpExportFormat): RtpExportKind =
            entries.first { it.format == format }
    }
}

data class RtpExportFailure(
    val streamId: String,
    val message: String
)

data class RtpExportSummary(
    val kind: RtpExportKind,
    val files: List<ExportResult>,
    val failures: List<RtpExportFailure>
) {
    val isSuccess: Boolean get() = failures.isEmpty()
    val isPartial: Boolean get() = files.isNotEmpty() && failures.isNotEmpty()
}

sealed interface RtpExportUiState {
    data object Idle : RtpExportUiState
    data class Running(
        val kind: RtpExportKind,
        val done: Int,
        val total: Int,
        /** 这一条流自己的进度。解码回调给的是百分数（`total == 100`）；还没有时为 null。 */
        val progress: RtpProgress? = null
    ) : RtpExportUiState

    data class Finished(
        val summary: RtpExportSummary,
        val shareResults: List<ExportResult> = emptyList()
    ) : RtpExportUiState

    data class Error(val message: String) : RtpExportUiState
}

/**
 * 「外部打开」的准备状态（RTP4-KT-03 卡片第 2 条）。
 *
 * [Ready] 的 [containerPath] 为空串表示「这条流没有原生容器格式」或者容器导不出来，
 * 调用方直接拿 WAV 去打开；非空时**先**试容器，[mimeType] 是该容器的 MIME，
 * `ExternalPlayerLauncher.open` 返回 false（没有应用能处理它）时再用 WAV 回退。
 */
sealed interface RtpExternalOpenUiState {
    data object Idle : RtpExternalOpenUiState
    data class Preparing(val streamId: String) : RtpExternalOpenUiState
    data class Ready(
        val streamId: String,
        val containerPath: String,
        val mimeType: String
    ) : RtpExternalOpenUiState

    data class Error(val message: String) : RtpExternalOpenUiState
}

/**
 * 一次视频导出的结果摘要（RTP5-KT-02）。
 *
 * [files] / [failures] 与音频的 [RtpExportSummary] 同形状，[results] 是视频多出来的一份：
 * 每条成功导出的流自己的原生结果。UI-01 的导出对话框要显示分辨率、帧数、损坏帧数与
 * 不支持的包型计数，那些数字只在 [RtpVideoExportResult] 里。
 */
data class RtpVideoExportSummary(
    val format: RtpVideoExportFormat,
    val files: List<ExportResult>,
    val failures: List<RtpExportFailure>,
    val results: Map<String, RtpVideoExportResult> = emptyMap()
) {
    val isSuccess: Boolean get() = failures.isEmpty()
    val isPartial: Boolean get() = files.isNotEmpty() && failures.isNotEmpty()
}

/**
 * 视频导出（MP4 / 裸流）的 UI 状态，形状照 [RtpExportUiState]。
 *
 * 单开一个状态而不是把两个视频格式塞进 [RtpExportKind]：那张表按 [RtpExportFormat]
 * 取值，而视频格式不在音频的表里（见 `model/RtpModels.kt` 的 `RtpVideoExportFormat`）。
 * 两个状态各自独立，谁也不会把对方的结果覆盖掉。
 */
/**
 * 一次视频导出正在做哪一段。
 *
 * 原生的 `exportRtpVideo` 要先把整份抓包遍历一遍（大文件上这是几分钟），MP4 还要再把
 * 每个访问单元写进封装器。两段都有自己的计数，界面用这个区分文案。
 */
enum class RtpVideoExportPhase {
    /** 原生遍历：进度是百分数，`total == 100`。 */
    EXTRACTING,

    /** 把基本流封装成 MP4：进度同样是百分数。 */
    MUXING
}

sealed interface RtpVideoExportUiState {
    data object Idle : RtpVideoExportUiState
    data class Running(
        val format: RtpVideoExportFormat,
        val done: Int,
        val total: Int,
        val phase: RtpVideoExportPhase = RtpVideoExportPhase.EXTRACTING,
        /** 当前阶段的进度。提取阶段 `total == 100`；封装阶段是访问单元数。 */
        val progress: RtpProgress? = null
    ) : RtpVideoExportUiState

    data class Finished(
        val summary: RtpVideoExportSummary,
        val shareResults: List<ExportResult> = emptyList()
    ) : RtpVideoExportUiState

    data class Error(val message: String) : RtpVideoExportUiState
}

/**
 * 「外部打开」的准备状态（RTP5-KT-02），形状照 [RtpExternalOpenUiState]。
 *
 * [mimeTypes] 的顺序就是回退顺序：首选 MIME 在前，`application/octet-stream` 在后 ——
 * 但**只有裸流有那一项**（卡片第 1 条只给裸流的「无处理应用」留了回退），MP4 就是
 * `video/mp4` 一个候选。调用方拿到 [Ready] 后按这个顺序建
 * [ExternalPlayerLauncher.ExternalOpenCandidate] 列表交给
 * [ExternalPlayerLauncher.openFirstAvailable]，见 [videoOpenCandidates]。
 *
 * 导出**失败**发布 [Error]，绝不降级成另一个文件：卡片说的回退条件是「没有应用能处理
 * 这个 MIME」，不是「这个文件导不出来」（README §4.5.4）。
 */
sealed interface RtpVideoOpenUiState {
    data object Idle : RtpVideoOpenUiState
    data class Preparing(
        val streamId: String,
        /** 与导出同一条原生遍历，百分数 `total == 100`。外部打开一样会很久。 */
        val progress: RtpProgress? = null
    ) : RtpVideoOpenUiState
    data class Ready(
        val streamId: String,
        val filePath: String,
        val mimeTypes: List<String>,
        val format: RtpVideoExportFormat
    ) : RtpVideoOpenUiState

    data class Error(val message: String) : RtpVideoOpenUiState
}

/**
 * RTP5-KT-04：音视频合成正在做哪一步。
 *
 * 三步对应三次真实的等待，而它们的长短差着数量级：音频重编码是逐块喂 PCM、十几秒的
 * 视频导出是一次原生遍历、封装自己只是按索引写样本。界面看不出区别就只能在黑屏里等，
 * 所以进度阶段是分开的（[RtpAvMuxUiState.Running] 的 `done`/`total` 只在
 * [AUDIO] 这一段有值 —— 那是 `AacExporter` 自己的样本帧计数）。
 */
enum class RtpAvMuxStage {
    /** 渲染 WAV，再用 `AacExporter` 把它编码成 `.m4a`。 */
    AUDIO,

    /** 原生的 `exportRtpVideo`：ES 与 `.vidx`。 */
    VIDEO,

    /** 把两路合成一个 MP4。 */
    MUXING
}

/**
 * 音视频合成（MP4 + AAC 轨）的 UI 状态，形状照 [RtpVideoOpenUiState]：
 * 单条流、要么成要么不成，所以成功是 [Finished]，失败是 [Error]，没有「部分成功」。
 *
 * [Finished] 带着封装器自己的数字（写进去的帧数与音频样本数、被丢掉的头部样本数、
 * 以及对齐用的偏移量）。它们不是装饰：卡片的重点是**对齐**，而偏移量只有封装器知道
 * 自己用的是哪一版 —— 把它发布出来，界面与测试看到的才是真的写进去的那个值。
 */
sealed interface RtpAvMuxUiState {
    data object Idle : RtpAvMuxUiState

    data class Running(
        val stage: RtpAvMuxStage,
        val done: Int = 0,
        val total: Int = 0
    ) : RtpAvMuxUiState

    data class Finished(
        val file: ExportResult,
        val videoFrames: Int,
        val audioSamples: Int,
        val droppedAudioSamples: Int,
        val audioOffsetUs: Long
    ) : RtpAvMuxUiState

    data class Error(val message: String) : RtpAvMuxUiState
}

/**
 * 应用内预览页的状态（RTP5-KT-03）。
 *
 * [accessUnits] 是 `.vidx` 读出来的访问单元，整页的「当前是第几包」与「哪些帧标红」都由它
 * 算出来（纯逻辑在 `ui/components/rtp/RtpVideoPreviewTimeline.kt`）。索引读失败**不影响
 * 播放**：[indexError] 说明缺了什么，视频照放，只是没有包号 —— 不能因为少了附加信息就
 * 把整个预览说成打不开（README §4.5.4）。
 */
data class RtpVideoPreviewUiState(
    val mp4Path: String = "",
    val indexPath: String = "",
    val accessUnits: List<VidxEntry> = emptyList(),
    val indexError: String? = null,
    /**
     * 打不开预览的原因；非空且 [isOpen] 为 false 时屏幕显示它。
     * 正常的播放失败走 [RtpPlayerState.Error]，不是这个字段。
     */
    val errorMessage: String? = null
) {
    val isOpen: Boolean get() = mp4Path.isNotBlank()

    /** 损坏帧的数量：进度条画的是区间，这个数是同一件事的可读版本。 */
    val corruptFrameCount: Int get() = accessUnits.count { it.isCorrupt }
}

/**
 * RTP 流扫描的 ViewModel（RTP1-KT-02）。
 *
 * 只依赖 [RtpRepository] 与 [CaptureSessionCoordinator]：扫描状态刻意不放进
 * `PacketListViewModel`（README §4.5.6 / C18）。
 *
 * 会话失效规则：`sessionHandle` / `sessionGeneration` / `analysisConfigVersion`
 * 任一变化（以及 `limitToDisplayFilter=true` 时 `filterRevision` 变化）都会取消
 * 正在跑的扫描、请求原生层取消、把状态重置为 [RtpScanUiState.Idle] 并清空覆盖表。
 *
 * [externalScope] 与 `ProtocolAgentViewModel` 一样可注入：JVM 单测没有 Main
 * dispatcher，必须传入；不传时才 `?:` 回落到 [viewModelScope]。
 */
class RtpViewModel(
    private val repository: RtpRepository,
    private val sessionCoordinator: CaptureSessionCoordinator,
    private val ioDispatcher: CoroutineDispatcher = Dispatchers.IO,
    externalScope: CoroutineScope? = null,
    val audioPlayerController: RtpAudioPlayerController? = null,
    private val mediaCache: RtpMediaCache? = null,
    private val cacheRoot: File? = null,
    /**
     * RTP5-KT-02：RTP5-KT-01 封装器的接缝。默认就是生产实现；JVM 单测注入一个
     * 不碰 `MediaMuxer` 的 fake，才能断言「ES 与索引被交给了封装器」。
     */
    private val videoMuxer: VideoMuxer = PlatformVideoMuxer(),
    /**
     * RTP5-KT-02：设备解码能力探针的接缝（唯一一处 `android.media.*` 调用在
     * `media/VideoDecoderProbe.kt`）。探针只影响**提示**，不拦任何导出路径。
     */
    private val videoDecoderProbe: VideoDecoderProbe = PlatformVideoDecoderProbe,
    /**
     * RTP5-KT-03：应用内预览的状态机接缝（`MediaPlayer` 那一半在
     * `media/RtpVideoPreviewController.kt`）。`null` 表示这台宿主没有配置预览 —— 所有预览
     * 入口在这种情况下都只是「没有状态可发布」，不会崩，也不会假装能播。
     *
     * 与 [audioPlayerController] 同一条接缝原则：JVM 单测注入一个不碰 `MediaPlayer` 的
     * fake 控制器，才能断言「拖动在准备期间被记下来了」这类规则。
     */
    private val videoPreviewController: RtpVideoPreviewController? = null,
    /**
     * RTP5-KT-04：音视频合成封装器的接缝（`MediaMuxer` + `MediaExtractor` 那一半在
     * `media/RtpAudioVideoMuxer.kt`）。默认就是生产实现；JVM 单测注入一个不碰
     * `android.media.*` 的 fake，才能断言「ES、索引与编码好的音频被交给了封装器，
     * 用的两个时间基准是这两条流自己的 `firstAbsEpochUs`」。
     *
     * 与 [videoMuxer] 分开而不是复用它：KT-01 的 `mux` 是冻结的七参数形状，带音频的
     * 那条路多一个音轨、多两个基准、多一份「丢了多少头部样本」的回报，硬塞进同一个
     * 签名只会让两边都变形。
     */
    private val avMuxer: AudioVideoMuxer = PlatformAudioVideoMuxer(),
    /**
     * RTP5-KT-04：M4-KT-04 的 AAC 编码器的接缝。默认就是生产实现（一个
     * `PlatformAacTrackExporter`，每次调用新建一个 `AacExporter`）。
     */
    private val aacExporter: AacTrackExporter = PlatformAacTrackExporter(),
    /**
     * RTP5-KT-04：设备有没有 AAC 编码器的接缝（唯一一处 `android.media.*` 调用在
     * `media/AacTrackExporter.kt`）。它只回答**可用性**，不参与任何导出判断：
     * 真的编码器拒绝，由 `AacExporter` 自己回 `noEncoder`。
     */
    private val aacEncoderProbe: AacEncoderProbe = PlatformAacEncoderProbe
) : ViewModel() {

    private val runScope: CoroutineScope = externalScope ?: viewModelScope

    private val _state = MutableStateFlow<RtpScanUiState>(RtpScanUiState.Idle)
    val state: StateFlow<RtpScanUiState> = _state.asStateFlow()

    /** 当前生效的动态 PT 覆盖表；由 [setOverride]/[clearOverrides]/[setPayloadOverrides] 维护。 */
    private val _overrides = MutableStateFlow<List<RtpPayloadOverride>>(emptyList())
    val overrides: StateFlow<List<RtpPayloadOverride>> = _overrides.asStateFlow()

    /** Stream id highlighted after navigation from packet details; auto-clears after 5 s. */
    private val _highlightedStreamId = MutableStateFlow<String?>(null)
    val highlightedStreamId: StateFlow<String?> = _highlightedStreamId.asStateFlow()

    private val _exportState = MutableStateFlow<RtpExportUiState>(RtpExportUiState.Idle)
    val exportState: StateFlow<RtpExportUiState> = _exportState.asStateFlow()

    private val _externalOpenState =
        MutableStateFlow<RtpExternalOpenUiState>(RtpExternalOpenUiState.Idle)
    val externalOpenState: StateFlow<RtpExternalOpenUiState> =
        _externalOpenState.asStateFlow()

    /** RTP5-KT-02：视频导出（MP4 / 裸流）的状态；与音频的 [exportState] 各自独立。 */
    private val _videoExportState =
        MutableStateFlow<RtpVideoExportUiState>(RtpVideoExportUiState.Idle)
    val videoExportState: StateFlow<RtpVideoExportUiState> = _videoExportState.asStateFlow()

    private val _videoOpenState =
        MutableStateFlow<RtpVideoOpenUiState>(RtpVideoOpenUiState.Idle)
    val videoOpenState: StateFlow<RtpVideoOpenUiState> = _videoOpenState.asStateFlow()

    /**
     * RTP5-KT-03：预览页的状态（打开的 MP4 + 它的 `.vidx`）。与播放状态分开：
     * 索引读失败时前者仍然 `isOpen`，后者照常播。
     */
    private val _videoPreview = MutableStateFlow(RtpVideoPreviewUiState())
    val videoPreview: StateFlow<RtpVideoPreviewUiState> = _videoPreview.asStateFlow()

    /**
     * RTP5-KT-04：「导出 MP4（含音频）」这个入口能不能给，UI-01 只按它决定显不显示。
     *
     * 默认 [RtpAvMuxAvailability.NoCall]：没有 M3 的关联结果就没有这条入口 —— 卡片
     * 要的是**不显示**，而不是一个按下去没用的灰按钮（与 KT-03 的
     * [RtpVideoPreviewAvailability] 同一条规则）。
     */
    private val _avMuxAvailability =
        MutableStateFlow<RtpAvMuxAvailability>(RtpAvMuxAvailability.NoCall)
    val avMuxAvailability: StateFlow<RtpAvMuxAvailability> = _avMuxAvailability.asStateFlow()

    /** RTP5-KT-04：音视频合成的导出状态；与视频导出（[videoExportState]）各自独立。 */
    private val _avMuxState = MutableStateFlow<RtpAvMuxUiState>(RtpAvMuxUiState.Idle)
    val avMuxState: StateFlow<RtpAvMuxUiState> = _avMuxState.asStateFlow()

    /**
     * RTP5-KT-03：「应用内预览」这个入口能不能给，UI-01 只按它决定显不显示。
     *
     * 默认 [RtpVideoPreviewAvailability.NoExport]：没有导出过就没有入口 —— 卡片要求的是
     * **不显示**，而不是显示一个按下去没用的灰按钮。
     */
    private val _videoPreviewAvailability =
        MutableStateFlow<RtpVideoPreviewAvailability>(RtpVideoPreviewAvailability.NoExport)
    val videoPreviewAvailability: StateFlow<RtpVideoPreviewAvailability> =
        _videoPreviewAvailability.asStateFlow()

    /** RTP5-KT-03：预览的播放状态；没有控制器时恒为 [RtpPlayerState.Idle]。 */
    private val idleVideoPreviewPlayback = MutableStateFlow<RtpPlayerState>(RtpPlayerState.Idle)
    val videoPreviewPlaybackState: StateFlow<RtpPlayerState> =
        videoPreviewController?.state ?: idleVideoPreviewPlayback.asStateFlow()

    private val idleVideoPreviewPosition = MutableStateFlow(0L)
    val videoPreviewPositionMs: StateFlow<Long> =
        videoPreviewController?.positionMs ?: idleVideoPreviewPosition.asStateFlow()

    private val idleVideoPreviewDuration = MutableStateFlow(0L)
    val videoPreviewDurationMs: StateFlow<Long> =
        videoPreviewController?.durationMs ?: idleVideoPreviewDuration.asStateFlow()

    /**
     * RTP5-KT-02：本机有没有 H.265 解码器（`MediaCodecList.findDecoderForFormat("video/hevc")`）。
     *
     * 卡片：没有解码器时给**提示**，但**仍然允许导出** —— 这个信号只给提示用，
     * 不参与任何一条导出路径的判断。UI-01 在 [RtpVideoDecoderAvailability.noticeRequired]
     * 为 true 时渲染 `R.string.rtp_video_hevc_decoder_missing`。
     */
    private val _hevcDecoderAvailability =
        MutableStateFlow(RtpVideoDecoderAvailability.UNKNOWN)
    val hevcDecoderAvailability: StateFlow<RtpVideoDecoderAvailability> =
        _hevcDecoderAvailability.asStateFlow()

    private val _playerState = MutableStateFlow(RtpPlayerUiState())
    val playerState: StateFlow<RtpPlayerUiState> = _playerState.asStateFlow()
    private var playerAutoPlay = true

    private val idlePlaybackState = MutableStateFlow<RtpPlayerState>(RtpPlayerState.Idle)
    val playerPlaybackState: StateFlow<RtpPlayerState> =
        audioPlayerController?.state ?: idlePlaybackState.asStateFlow()

    private val idlePlayerPosition = MutableStateFlow(0L)
    val playerPositionMs: StateFlow<Long> =
        audioPlayerController?.positionMs ?: idlePlayerPosition.asStateFlow()

    private var scanJob: Job? = null
    private var highlightJob: Job? = null
    private var exportJob: Job? = null
    private var externalOpenJob: Job? = null
    private var playerDecodeJob: Job? = null
    private var videoExportJob: Job? = null
    private var videoOpenJob: Job? = null

    /**
     * 用户点了「取消」之后，下一次进度回调回 false，原生遍历就此停下。
     * 不取消协程本身：原生调用还在 JNI 里，要等它带着 `cancelled` 返回再清理目录。
     */
    @Volatile
    private var videoExportCancelRequested = false

    @Volatile
    private var audioExportCancelRequested = false
    private var videoPreviewJob: Job? = null
    private var videoPreviewAvailabilityJob: Job? = null
    private var avMuxJob: Job? = null
    private var avMuxAvailabilityJob: Job? = null

    /** 自增的请求号：结果返回时与它比较，过期结果直接丢弃。 */
    private var requestId = 0L

    /** 自增的媒体请求号；每个渲染批次使用独立缓存目录。 */
    private var mediaRequestId = 0L

    /** 自增的播放器解码请求号；旧结果不得覆盖新时序/新流。 */
    private var playerDecodeRequestId = 0L

    private var playerDecodeSessionHandle: Long? = null
    private var playerDecodeMediaRequestId: Long? = null

    /** 已经渲染且通过缓存根校验的 WAV，按会话、流和时序参数复用。 */
    private val decodedWavFiles = mutableMapOf<DecodedWavKey, File>()

    /** 最近一次 [scan] 使用的 `limitToDisplayFilter`，重扫时必须沿用同一个值。 */
    private var lastLimitToDisplayFilter = false

    /** `(sessionHandle, sessionGeneration, analysisConfigVersion)` 三元组的记忆。 */
    private var lastSessionKey: SessionKey? = null

    /** `filterRevision` 的记忆；只在 `limitToDisplayFilter=true` 时参与比较。 */
    private var lastFilterRevision: Long = 0L

    init {
        runScope.launch {
            sessionCoordinator.state.collect { session ->
                val key = SessionKey(
                    sessionHandle = session.sessionHandle,
                    sessionGeneration = session.sessionGeneration,
                    analysisConfigVersion = session.analysisConfigVersion
                )
                val previousKey = lastSessionKey
                val previousRevision = lastFilterRevision
                // 第一次收到状态时只记录：构造完就立刻空跑一次重置是没有意义的。
                lastSessionKey = key
                lastFilterRevision = session.filterRevision
                if (previousKey == null) return@collect

                val sessionChanged = previousKey != key
                val filterChanged = lastLimitToDisplayFilter && previousRevision != session.filterRevision
                if (sessionChanged || filterChanged) {
                    resetForInvalidation()
                }
            }
        }
    }

    /**
     * 扫描当前会话的 RTP 流。
     *
     * @param limitToDisplayFilter 跟随「只分析当前过滤结果」开关，默认 false
     */
    fun scan(limitToDisplayFilter: Boolean = false) {
        lastLimitToDisplayFilter = limitToDisplayFilter
        val request = ++requestId
        scanJob?.cancel()
        _state.value = RtpScanUiState.Running(0, 0)
        // LAZY + start()：先让 scanJob 指向本次 Job，协程体才开始跑。否则
        // Unconfined/Main.immediate 下协程体会在 launch 返回前就执行，
        // 回调里触发的 cancel() 会看到过期的 scanJob。
        val job = runScope.launch(start = CoroutineStart.LAZY) {
            val result = try {
                withContext(ioDispatcher) {
                    repository.scanRtpStreams(limitToDisplayFilter) { progress ->
                        if (request == requestId) {
                            _state.value = RtpScanUiState.Running(progress.done, progress.total)
                        }
                        true
                    }
                }
            } catch (cancelled: CancellationException) {
                // 取消不是失败：这里不提交任何状态，交由 cancel()/失效规则负责。
                throw cancelled
            } catch (error: Throwable) {
                if (request == requestId) {
                    _state.value = RtpScanUiState.Error(error.message ?: SCAN_FAILED_MESSAGE)
                }
                return@launch
            }
            if (request != requestId) return@launch
            _state.value = when {
                result.cancelled -> RtpScanUiState.Cancelled
                result.error.isNotEmpty() -> RtpScanUiState.Error(result.error)
                else -> RtpScanUiState.Done(result)
            }
        }
        scanJob = job
        job.start()
    }

    /** Highlights one stream and clears the highlight after five seconds. */
    fun highlightStream(streamId: String?) {
        highlightJob?.cancel()
        _highlightedStreamId.value = streamId
        if (streamId == null) return
        highlightJob = runScope.launch {
            delay(HIGHLIGHT_DURATION_MS)
            if (_highlightedStreamId.value == streamId) _highlightedStreamId.value = null
        }
    }

    /**
     * 停下正在进行的视频导出或「外部播放」准备。
     *
     * 大文件的原生遍历要几分钟，进度条旁边必须能停。`cancelLongRunningOperations`
     * 让遍历在下一帧退出；进度回调回 false 是同一条取消的另一路。封装阶段则停在
     * 当前访问单元。
     */
    fun cancelVideoExport() {
        videoExportCancelRequested = true
        sessionCoordinator.cancelLongRunningOperations()
        videoMuxer.cancel()
    }

    /** 停下正在进行的音频导出。解码循环同样看这个标志和长操作取消。 */
    fun cancelAudioExport() {
        audioExportCancelRequested = true
        sessionCoordinator.cancelLongRunningOperations()
    }

    /** 用户主动停止扫描。 */
    fun cancel() {
        // 令在途结果失效，避免它稍后返回时覆盖 Cancelled。
        requestId += 1
        scanJob?.cancel()
        sessionCoordinator.cancelLongRunningOperations()
        _state.value = RtpScanUiState.Cancelled
    }

    /**
     * Opens the RTP player for one or more streams.
     *
     * RTP2-UI-02 passes one stream; the list is retained for the UI-03 tab
     * switcher without changing the decode request shape.
     * Card navigation disables [autoPlay]; explicit play actions keep it enabled.
     */
    fun openPlayer(
        streams: List<RtpStream>,
        selectedStreamId: String = streams.firstOrNull()?.id.orEmpty(),
        autoPlay: Boolean = true
    ) {
        val selected = streams.firstOrNull { it.id == selectedStreamId }
            ?: streams.firstOrNull()
            ?: return
        playerAutoPlay = autoPlay
        _playerState.value = RtpPlayerUiState(
            streams = streams,
            selectedStreamId = selected.id
        )
        decodePlayer()
    }

    /** Convenience entry for the single-stream card menu. */
    fun openPlayerStream(stream: RtpStream) {
        openPlayer(listOf(stream), stream.id)
    }

    /**
     * Switches the active tab when the decoded result already exists.
     * Missing items are decoded on demand for forward compatibility with UI-03.
     */
    fun selectPlayerStream(streamId: String) {
        val current = _playerState.value
        if (current.streams.none { it.id == streamId } || current.selectedStreamId == streamId) {
            return
        }
        val item = current.decodedItems.firstOrNull { it.streamId == streamId }
        if (item != null) {
            _playerState.value = current.copy(
                selectedStreamId = streamId,
                status = RtpPlayerDecodeStatus.READY,
                errorMessage = null
            )
            loadPlayerSource(item)
        } else {
            _playerState.value = current.copy(
                selectedStreamId = streamId,
                status = RtpPlayerDecodeStatus.IDLE,
                errorMessage = null
            )
            decodePlayer()
        }
    }

    /** Re-renders the current stream with a different timing mode. */
    fun setPlayerTiming(timing: RtpTimingMode) {
        val current = _playerState.value
        if (!current.isOpen || current.timing == timing) return
        _playerState.value = current.copy(timing = timing)
        decodePlayer()
    }

    fun playPlayer() {
        audioPlayerController?.play()
    }

    fun pausePlayer() {
        audioPlayerController?.pause()
    }

    fun seekPlayer(positionMs: Long) {
        audioPlayerController?.seekTo(positionMs)
    }

    /** Retries the last failed/cancelled decode request. */
    fun retryPlayerDecode() {
        if (_playerState.value.isOpen) decodePlayer()
    }

    /** Cancels decoding and removes the request directory owned by this attempt. */
    fun cancelPlayerDecode() {
        val current = _playerState.value
        if (!current.isOpen) return

        playerDecodeRequestId += 1
        playerDecodeJob?.cancel()
        playerDecodeJob = null
        sessionCoordinator.cancelLongRunningOperations()
        deletePlayerDecodeRequest()
        _playerState.value = current.copy(
            status = RtpPlayerDecodeStatus.CANCELLED,
            progress = null,
            decodedItems = emptyList(),
            unsupported = emptyList(),
            errorMessage = null
        )
    }

    /** Closes the player and releases its media request, but keeps the controller reusable. */
    fun closePlayer() {
        val current = _playerState.value
        playerDecodeRequestId += 1
        playerDecodeJob?.cancel()
        playerDecodeJob = null
        sessionCoordinator.cancelLongRunningOperations()
        // Keep completed output until the next player request or session close:
        // an in-flight export/share may still be reading the WAV.
        if (current.status != RtpPlayerDecodeStatus.READY || current.selectedItem == null) {
            deletePlayerDecodeRequest()
        }
        audioPlayerController?.pause()
        _playerState.value = RtpPlayerUiState()
    }

    /**
     * 整体替换会话级动态 PT 覆盖表（KT-04 用）。
     *
     * 写入失败（`error` 非空）时把覆盖表回滚到调用前的快照；成功则按上一次的
     * `limitToDisplayFilter` 自动重扫。
     */
    fun setPayloadOverrides(overrides: List<RtpPayloadOverride>) {
        val previous = _overrides.value
        _overrides.value = overrides
        runScope.launch {
            val result = try {
                withContext(ioDispatcher) { repository.setRtpPayloadOverrides(overrides) }
            } catch (cancelled: CancellationException) {
                throw cancelled
            } catch (error: Throwable) {
                _overrides.value = previous
                _state.value = RtpScanUiState.Error(error.message ?: OVERRIDE_FAILED_MESSAGE)
                return@launch
            }
            if (result.error.isNotEmpty()) {
                // fail-closed：原生层拒绝了这次写入，本地覆盖表必须回到原样。
                _overrides.value = previous
                _state.value = RtpScanUiState.Error(result.error)
            } else {
                scan(lastLimitToDisplayFilter)
            }
        }
    }

    /**
     * 给某个动态 PT 指定编码（KT-04）。成功后自动按上一次的 `limitToDisplayFilter` 重扫。
     *
     * 同一个 [pt] 是**替换**而不是追加；覆盖表按 `pt` 排序以让 JSON 可复现。
     * [codecId] 先经 [RtpCodecCatalog.byId] 归一化成规范 ID（大小写不敏感），
     * 未命中时原样保留，交给原生层 fail-closed 判定；`channels` 同样取自目录
     * （未命中回落到 1）。写入与回滚/重扫语义全部委托给 [setPayloadOverrides]。
     */
    fun setOverride(pt: Int, codecId: String, clockRate: Int) {
        val entry = RtpCodecCatalog.byId(codecId)
        val next = (
            _overrides.value.filterNot { it.pt == pt } +
                RtpPayloadOverride(pt, entry?.id ?: codecId, clockRate, entry?.channels ?: 1)
            ).sortedBy { it.pt }
        setPayloadOverrides(next)
    }

    /** 清空会话级覆盖表并重扫。 */
    fun clearOverrides() {
        setPayloadOverrides(emptyList())
    }

    /**
     * Renders missing WAV sources, then copies each one to its SAF destination.
     * Every stream is attempted even when an earlier stream fails.
     */
    fun exportWav(
        streams: List<RtpStream>,
        destinations: List<RtpExportDestination>,
        timing: RtpTimingMode = RtpTimingMode.JITTER,
        jitterMs: Int = 50
    ) {
        startExport(
            kind = RtpExportKind.WAV,
            streams = streams,
            destinations = destinations,
            timing = timing,
            jitterMs = jitterMs,
            share = false
        )
    }

    /**
     * Exports raw RTP payload files through [RtpRepository.exportRaw], then
     * copies each temporary file to its SAF destination.
     */
    fun exportRaw(
        streams: List<RtpStream>,
        destinations: List<RtpExportDestination>,
        order: RtpRawOrder = RtpRawOrder.SEQ
    ) {
        startExport(
            kind = RtpExportKind.RAW,
            streams = streams,
            destinations = destinations,
            order = order,
            share = false
        )
    }

    /** Prepares cached WAV files and publishes them for the UI share helper. */
    fun shareWav(
        streams: List<RtpStream>,
        timing: RtpTimingMode = RtpTimingMode.JITTER,
        jitterMs: Int = 50
    ) {
        startExport(
            kind = RtpExportKind.WAV,
            streams = streams,
            destinations = null,
            timing = timing,
            jitterMs = jitterMs,
            share = true
        )
    }

    /** Prepares raw payload files and publishes them for the UI share helper. */
    fun shareRaw(
        streams: List<RtpStream>,
        order: RtpRawOrder = RtpRawOrder.SEQ
    ) {
        startExport(
            kind = RtpExportKind.RAW,
            streams = streams,
            destinations = null,
            order = order,
            share = true
        )
    }

    /**
     * RTP4-KT-03：按导出格式保存一条流（导出格式对话框的唯一入口）。
     *
     * WAV / 裸流原样转给既有的 [exportWav] / [exportRaw]（两者的签名与行为都没变），
     * 容器格式转给 [exportContainer]。三条路径共用同一份缓存目录与命名口径，结果都
     * 落在 [exportState] 上。
     */
    fun exportFormat(
        stream: RtpStream,
        format: RtpExportFormat,
        destination: RtpExportDestination
    ) {
        when (format) {
            RtpExportFormat.WAV -> exportWav(listOf(stream), listOf(destination))
            RtpExportFormat.RAW -> exportRaw(listOf(stream), listOf(destination))
            RtpExportFormat.AMR,
            RtpExportFormat.AWB,
            RtpExportFormat.OPUS -> exportContainer(listOf(stream), format, listOf(destination))
        }
    }

    /**
     * 导出容器文件（`.amr` / `.awb` / `.opus`，RTP4-KT-03）。
     *
     * [format] 必须是容器格式，且与流自己的编码一致 —— 调用方按
     * `RtpCodecCatalog.containerFormat(stream.codec)` 取（原生的
     * `exportRtpContainer` 会校验两者是否一致，不一致直接回
     * `error="format does not match the stream codec."`）。不一致的流在这里就作为
     * 该路的失败记录下来，请求根本不发。
     */
    fun exportContainer(
        streams: List<RtpStream>,
        format: RtpExportFormat,
        destinations: List<RtpExportDestination>
    ) {
        startExport(
            kind = RtpExportKind.of(format),
            streams = streams,
            destinations = destinations,
            share = false
        )
    }

    /** Prepares container files and publishes them for the UI share helper. */
    fun shareContainer(streams: List<RtpStream>, format: RtpExportFormat) {
        startExport(
            kind = RtpExportKind.of(format),
            streams = streams,
            destinations = null,
            share = true
        )
    }

    fun clearExportState() {
        _exportState.value = RtpExportUiState.Idle
    }

    /**
     * RTP4-KT-03 卡片第 2 条：「外部打开」优先原生容器，失败回退 WAV。
     *
     * 本函数只做**首选**那一半：把流导出成原生容器文件，结果通过 [externalOpenState]
     * 发布。调用方拿到 [RtpExternalOpenUiState.Ready] 后按「容器 → WAV」的顺序调用
     * `ExternalPlayerLauncher.openFirstAvailable`：容器没有应用能处理时，用播放器
     * 已经渲染好的 WAV 再试一次（回退的判定就是 `open` 返回 `false`）。
     *
     * 编码没有容器格式（`RtpCodecCatalog.containerFormat` 为 null）时直接发布
     * 容器路径为空的 [RtpExternalOpenUiState.Ready]，不调 JNI。
     *
     * 导出**失败**（原生层拒收或写文件失败）发布 [RtpExternalOpenUiState.Error]：
     * 卡片说的回退条件是「没有应用能处理这个 MIME」，不是「容器导不出来」，把后者
     * 静默降级成 WAV 会把真正的错误藏起来（README §4.5.4）。
     */
    fun prepareExternalOpen(stream: RtpStream) {
        externalOpenJob?.cancel()
        externalOpenJob = null

        val cache = mediaCache
        val root = cacheRoot ?: cache?.rootDir
        if (cache == null || root == null) {
            _externalOpenState.value =
                RtpExternalOpenUiState.Error(EXPORT_CACHE_UNAVAILABLE_MESSAGE)
            return
        }
        val sessionHandle = sessionCoordinator.state.value.sessionHandle
        if (sessionHandle == 0L) {
            _externalOpenState.value = RtpExternalOpenUiState.Error(EXPORT_NO_SESSION_MESSAGE)
            return
        }
        val scanResult = (_state.value as? RtpScanUiState.Done)?.result
        if (scanResult == null || !scanResult.isSuccess) {
            _externalOpenState.value =
                RtpExternalOpenUiState.Error(EXPORT_SCAN_REQUIRED_MESSAGE)
            return
        }

        val format = RtpCodecCatalog.containerFormat(stream.codec)
            ?.takeIf { stream.decodable == RtpDecodability.YES }
        if (format == null) {
            _externalOpenState.value = RtpExternalOpenUiState.Ready(stream.id, "", "")
            return
        }

        _externalOpenState.value = RtpExternalOpenUiState.Preparing(stream.id)
        val job = runScope.launch(start = CoroutineStart.LAZY) {
            val outcome = withContext(ioDispatcher) {
                try {
                    Result.success(
                        exportContainerSource(
                            stream = stream,
                            scanGeneration = scanResult.scanGeneration,
                            sessionHandle = sessionHandle,
                            cache = cache,
                            cacheRoot = root,
                            format = format
                        )
                    )
                } catch (cancelled: CancellationException) {
                    throw cancelled
                } catch (error: Throwable) {
                    Result.failure(error)
                }
            }
            _externalOpenState.value = outcome.fold(
                onSuccess = { file ->
                    RtpExternalOpenUiState.Ready(
                        streamId = stream.id,
                        containerPath = file.absolutePath,
                        mimeType = format.mimeType
                    )
                },
                onFailure = { error ->
                    RtpExternalOpenUiState.Error(
                        error.message ?: EXPORT_CONTAINER_FAILED_MESSAGE
                    )
                }
            )
        }
        externalOpenJob = job
        job.start()
    }

    fun clearExternalOpenState() {
        _externalOpenState.value = RtpExternalOpenUiState.Idle
    }

    /**
     * RTP5-KT-02：把视频流导出成 [format]（MP4 或裸流）并写到 SAF 目的地。
     *
     * 与 [exportRaw] / [exportContainer] 的分工相同：本函数只做「准备 + 发布状态」，
     * 真正的活在 [performVideoExport] 里，结果落在 [videoExportState] 上。
     *
     * [paramSets] 是这条流 SDP 里的参数集（RTP5-KT-00 的 `SdpVideoParams.from`）。
     * **今天没有任何调用方给得出它**：RTP3-NAT-04 的 `readRtpSetupInfo` 在本仓库还不存在，
     * 没有 SDP fmtp 的来源（`SdpVideoParams.kt` 的头注释同此结论），所以缺省 null 就是
     * 「调用方不知道」。缺了它有三个可见后果，都在这里说清楚，不要到别处去猜：
     *
     *  - 请求里不会有 `paramSets` 键，原生层只能靠**带内**参数集。流里有 SPS 时宽高照常
     *    解析出来（`widthSource` 不带 `unknown`）；带内也没有时整个请求回「缺少参数集
     *    （SDP 与带内均未找到）」，本次导出记成失败，**不写任何文件**。
     *  - MP4 的轨道描述需要参数集（KT-01 的 `VideoMuxFormat.codecSpecificData` 缺 SPS/PPS
     *    会 fail-closed）。它按 [videoTrackParamSets] 的顺序取：SDP 的 [paramSets] 优先，
     *    其次用原生结果里的 `csd` —— 那是生产方对「写出的 ES 开头带的是哪组参数集」的
     *    权威回答，所以**带内有 SPS/PPS 的流（卡片第二个 H.264 夹具就是这一类）今天就能
     *    导出 MP4**。两个来源都为空时才是 `missingParameterSets` 这个失败 ——
     *    不是静默降级成裸流（README §4.5.4）。
     *  - 裸流那条路不经过封装器，也不看参数集，带内有没有都能用。
     *
     * 不要为了让 MP4 通过而在 Kotlin 侧读 fmtp 或凭空造参数集：`csd` 是原生层给的字节，
     * SDP 这一路要等 `readRtpSetupInfo` 落地（`RtpRepository.exportVideo` 同此口径）。
     */
    fun exportVideo(
        streams: List<RtpStream>,
        format: RtpVideoExportFormat,
        destinations: List<RtpExportDestination>,
        startAtKeyframe: Boolean = true,
        dropCorrupt: Boolean = false,
        paramSets: VideoParamSets? = null
    ) {
        startVideoExport(
            format = format,
            streams = streams,
            destinations = destinations,
            startAtKeyframe = startAtKeyframe,
            dropCorrupt = dropCorrupt,
            paramSets = paramSets,
            share = false
        )
    }

    /** 准备视频文件并通过 [videoExportState] 的 `shareResults` 交给分享入口。 */
    fun shareVideo(
        streams: List<RtpStream>,
        format: RtpVideoExportFormat,
        startAtKeyframe: Boolean = true,
        dropCorrupt: Boolean = false,
        paramSets: VideoParamSets? = null
    ) {
        startVideoExport(
            format = format,
            streams = streams,
            destinations = null,
            startAtKeyframe = startAtKeyframe,
            dropCorrupt = dropCorrupt,
            paramSets = paramSets,
            share = true
        )
    }

    fun clearVideoExportState() {
        _videoExportState.value = RtpVideoExportUiState.Idle
    }

    /**
     * RTP5-KT-02 卡片第 1 条：「外部打开」视频流。
     *
     * 本函数只做**准备**那一半（与 [prepareExternalOpen] 同理）：把流出成 [format]
     * 并发布 [RtpVideoOpenUiState.Ready]，[mimeTypes] 就是外部打开的候选顺序。
     * 打开本身由调用方做（它才有 `Context`）：
     * `ExternalPlayerLauncher.openFirstAvailable(context, videoOpenCandidates(file, mimeTypes))`。
     *
     * 导出失败发布 [RtpVideoOpenUiState.Error]：视频没有「容器 → WAV」那种第二次机会，
     * 把失败静默换成别的文件会把真正的错误藏起来（README §4.5.4）。
     */
    fun prepareExternalVideoOpen(
        stream: RtpStream,
        format: RtpVideoExportFormat = RtpVideoExportFormat.RAW,
        startAtKeyframe: Boolean = true,
        dropCorrupt: Boolean = false,
        paramSets: VideoParamSets? = null
    ) {
        videoOpenJob?.cancel()
        videoOpenJob = null

        val cache = mediaCache
        val root = cacheRoot ?: cache?.rootDir
        if (cache == null || root == null) {
            _videoOpenState.value =
                RtpVideoOpenUiState.Error(EXPORT_CACHE_UNAVAILABLE_MESSAGE)
            return
        }
        val sessionHandle = sessionCoordinator.state.value.sessionHandle
        if (sessionHandle == 0L) {
            _videoOpenState.value = RtpVideoOpenUiState.Error(EXPORT_NO_SESSION_MESSAGE)
            return
        }
        val scanResult = (_state.value as? RtpScanUiState.Done)?.result
        if (scanResult == null || !scanResult.isSuccess) {
            _videoOpenState.value = RtpVideoOpenUiState.Error(EXPORT_SCAN_REQUIRED_MESSAGE)
            return
        }
        if (rtpVideoCodecId(stream.codec) == null || stream.decodable != RtpDecodability.YES) {
            _videoOpenState.value =
                RtpVideoOpenUiState.Error(EXPORT_VIDEO_UNSUPPORTED_MESSAGE)
            return
        }

        refreshHevcDecoderAvailabilityFor(stream)
        videoExportCancelRequested = false
        _videoOpenState.value = RtpVideoOpenUiState.Preparing(
            streamId = stream.id,
            progress = RtpProgress(0, 100)
        )
        val job = runScope.launch(start = CoroutineStart.LAZY) {
            val outcome = withContext(ioDispatcher) {
                try {
                    Result.success(
                        exportVideoSource(
                            stream = stream,
                            scanGeneration = scanResult.scanGeneration,
                            sessionHandle = sessionHandle,
                            cache = cache,
                            cacheRoot = root,
                            format = format,
                            startAtKeyframe = startAtKeyframe,
                            dropCorrupt = dropCorrupt,
                            paramSets = paramSets
                        )
                    )
                } catch (cancelled: CancellationException) {
                    throw cancelled
                } catch (error: Throwable) {
                    Result.failure(error)
                }
            }
            _videoOpenState.value = outcome.fold(
                onSuccess = { source ->
                    RtpVideoOpenUiState.Ready(
                        streamId = stream.id,
                        filePath = source.file.absolutePath,
                        mimeTypes = videoOpenMimeTypes(stream.codec, format),
                        format = format
                    )
                },
                onFailure = { error ->
                    RtpVideoOpenUiState.Error(error.message ?: EXPORT_VIDEO_FAILED_MESSAGE)
                }
            )
        }
        videoOpenJob = job
        job.start()
    }

    fun clearVideoOpenState() {
        _videoOpenState.value = RtpVideoOpenUiState.Idle
    }

    /**
     * RTP5-UI-01：视频流的**整卡点击** —— 一步封装出 MP4 并打开应用内预览。
     *
     * ### 为什么需要这一步
     *
     * 整卡点击原先调 [openVideoPreview]，而它的两个入参（`mp4Path` / `indexPath`）只由
     * **导出成功后**才有：宿主在 [RtpViewModel.videoExportState] 报 `Finished` 时才把
     * 「这份 MP4 属于哪条流」记进账（`PacketListScreen` 的 `videoPreviewTargets`）。于是
     * 在用户第一次导出之前，视频流的卡片点击拿不到任何路径 —— 这条入口只能给出一句
     * 「请用菜单里的『导出 MP4』」，而用户点的是**卡片**，不是菜单。
     *
     * 现在这条路径自己把中间产物准备好：[exportVideoSource] 把 ES 与 MP4 写进
     * [RtpMediaCache] 的请求目录（与 SAF 导出共用同一段实现，所以封装参数、fail-closed
     * 的原因、`.vidx` 的写法全都一致），然后把路径交给 [openVideoPreview]。
     * **不弹 SAF、不写用户可见的文件**：预览只读缓存，缓存随 [RtpMediaCache] 管理。
     * 想真的存下来仍然走 ⋮ 菜单的「导出 MP4」，那一步的落盘语义没有变。
     *
     * ### 失败一律 publish，不静默回退
     *
     * 封装失败（缺参数集、这条流不 decodable、扫描代际过期、会话已关闭）都落到
     * [_videoOpenState] 的 `Error` 上，由 UI 显示；**不会**悄悄退回音频播放器，
     * 也不会生成一个空 MP4 让播放器报「格式不支持」—— 那两种表现都会把「导出失败」
     * 说成「这条流坏了」（README §4.5.4）。
     *
     * H.265 走同一条路：[refreshHevcDecoderAvailabilityFor] 先探一次解码器，
     * `computeVideoPreviewAvailability` 在没有解码器时给出 `UnsupportedCodec`，
     * 预览页显示 [PREVIEW_NO_DECODER_MESSAGE]。**不因为「本机解不了」就拒绝导出** ——
     * 用户要的产物可能就是要拷到别的机器上看。
     */
    fun prepareVideoPreview(stream: RtpStream) {
        videoOpenJob?.cancel()
        videoOpenJob = null

        val cache = mediaCache
        val root = cacheRoot ?: cache?.rootDir
        if (cache == null || root == null) {
            _videoOpenState.value =
                RtpVideoOpenUiState.Error(EXPORT_CACHE_UNAVAILABLE_MESSAGE)
            return
        }
        val sessionHandle = sessionCoordinator.state.value.sessionHandle
        if (sessionHandle == 0L) {
            _videoOpenState.value = RtpVideoOpenUiState.Error(EXPORT_NO_SESSION_MESSAGE)
            return
        }
        val scanResult = (_state.value as? RtpScanUiState.Done)?.result
        if (scanResult == null || !scanResult.isSuccess) {
            _videoOpenState.value = RtpVideoOpenUiState.Error(EXPORT_SCAN_REQUIRED_MESSAGE)
            return
        }
        if (rtpVideoCodecId(stream.codec) == null || stream.decodable != RtpDecodability.YES) {
            _videoOpenState.value =
                RtpVideoOpenUiState.Error(EXPORT_VIDEO_UNSUPPORTED_MESSAGE)
            return
        }

        refreshHevcDecoderAvailabilityFor(stream)
        videoExportCancelRequested = false
        _videoOpenState.value = RtpVideoOpenUiState.Preparing(
            streamId = stream.id,
            progress = RtpProgress(0, 100)
        )
        val job = runScope.launch(start = CoroutineStart.LAZY) {
            val outcome = withContext(ioDispatcher) {
                try {
                    Result.success(
                        exportVideoSource(
                            stream = stream,
                            scanGeneration = scanResult.scanGeneration,
                            sessionHandle = sessionHandle,
                            cache = cache,
                            cacheRoot = root,
                            format = RtpVideoExportFormat.MP4,
                            startAtKeyframe = true,
                            dropCorrupt = false,
                            paramSets = null
                        )
                    )
                } catch (cancelled: CancellationException) {
                    throw cancelled
                } catch (error: Throwable) {
                    Result.failure(error)
                }
            }
            outcome.fold(
                onSuccess = { source ->
                    // File preparation has finished. Playback has its own state;
                    // leaving Preparing here keeps the list's progress banner at
                    // 100% even after the preview is closed.
                    _videoOpenState.value = RtpVideoOpenUiState.Idle
                    // 缓存路径交给预览页；`.vidx` 读不出来只影响包号那一行，视频照放
                    // （`openVideoPreview` 内部已经这样处理，这里不重复它的判定）。
                    openVideoPreview(stream, source.file.absolutePath, source.result.indexPath)
                },
                onFailure = { error ->
                    _videoOpenState.value =
                        RtpVideoOpenUiState.Error(error.message ?: EXPORT_VIDEO_FAILED_MESSAGE)
                }
            )
        }
        videoOpenJob = job
        job.start()
    }

    /**
     * RTP5-KT-03：这条流 + 这两个文件能不能用应用内预览。**只发布结论**，不碰播放器，
     * 也不改预览页的状态 —— UI-01 在把「应用内预览」放进菜单之前问它一次，
     * 结果落在 [videoPreviewAvailability] 上。
     *
     * 与 [openVideoPreview] 共用同一套判定（[computeVideoPreviewAvailability]），所以
     * 「菜单里能点」与「点下去能放开」不会出现两种答案。
     */
    fun refreshVideoPreviewAvailability(
        stream: RtpStream,
        mp4Path: String,
        indexPath: String
    ) {
        videoPreviewAvailabilityJob?.cancel()
        val job = runScope.launch(start = CoroutineStart.LAZY) {
            _videoPreviewAvailability.value =
                computeVideoPreviewAvailability(stream, mp4Path, indexPath)
        }
        videoPreviewAvailabilityJob = job
        job.start()
    }

    /**
     * RTP5-KT-03：打开应用内预览。
     *
     * @param stream 要预览的流（编码决定要不要问解码器）
     * @param mp4Path KT-01 封装出来的 MP4（UI-01 从导出摘要的 `files` 里拿）
     * @param indexPath 同一次导出留下的 `.vidx`（`RtpVideoExportResult.indexPath`），
     *   包号查找与损坏帧标红都靠它
     *
     * 不可预览时**不静默关掉**（README §4.5.4）：[videoPreviewAvailability] 给出结论，
     * 预览页的状态里带上同一件事的错误文本。索引读不出来只影响包号那一行，视频照放。
     */
    fun openVideoPreview(stream: RtpStream, mp4Path: String, indexPath: String) {
        videoPreviewJob?.cancel()
        videoPreviewJob = null

        val job = runScope.launch(start = CoroutineStart.LAZY) {
            val availability = computeVideoPreviewAvailability(stream, mp4Path, indexPath)
            _videoPreviewAvailability.value = availability

            when (availability) {
                is RtpVideoPreviewAvailability.Ready -> {
                    val index = withContext(ioDispatcher) {
                        try {
                            Result.success(VidxFile.read(File(availability.indexPath)).entries)
                        } catch (cancelled: CancellationException) {
                            throw cancelled
                        } catch (error: Throwable) {
                            Result.failure(error)
                        }
                    }
                    _videoPreview.value = index.fold(
                        onSuccess = { entries ->
                            RtpVideoPreviewUiState(
                                mp4Path = availability.mp4Path,
                                indexPath = availability.indexPath,
                                accessUnits = entries
                            )
                        },
                        onFailure = { error ->
                            RtpVideoPreviewUiState(
                                mp4Path = availability.mp4Path,
                                indexPath = availability.indexPath,
                                indexError = error.message ?: PREVIEW_INDEX_FAILED_MESSAGE
                            )
                        }
                    )
                    videoPreviewController?.load(availability.mp4Path)
                }

                is RtpVideoPreviewAvailability.UnsupportedCodec -> {
                    videoPreviewController?.pause()
                    _videoPreview.value = RtpVideoPreviewUiState(
                        errorMessage = PREVIEW_NO_DECODER_MESSAGE
                    )
                }

                RtpVideoPreviewAvailability.NoExport -> {
                    videoPreviewController?.pause()
                    _videoPreview.value = RtpVideoPreviewUiState(
                        errorMessage = PREVIEW_MISSING_MESSAGE
                    )
                }
            }
        }
        videoPreviewJob = job
        job.start()
    }

    fun playVideoPreview() {
        videoPreviewController?.play()
    }

    fun pauseVideoPreview() {
        videoPreviewController?.pause()
    }

    /**
     * 拖动预览。播放器还没准备好、或者上一次拖动还在路上时，控制器会把位置记下来而不是
     * 硬调 `seekTo`（见 `RtpVideoPreviewController`）；位置本身立刻发布，所以界面上的
     * 播放头跟着手指走。
     */
    fun seekVideoPreview(positionMs: Long) {
        videoPreviewController?.seekTo(positionMs)
    }

    /**
     * RTP5-UI-01：把预览页 `TextureView` 的 Surface 交给（或从）播放器。
     *
     * 这两次转发是 UI-01 才需要的：KT-03 的控制器早就有 `attachSurface`/`detachSurface`
     * （Surface 的生命周期与重组无关，见它的注释），但控制器是构造参数，**宿主拿不到它** ——
     * 预览页要把 Surface 递进来，只能走 ViewModel 的这道门。
     *
     * 转发是**幂等**且可早于 [openVideoPreview] 的：`TextureView` 的
     * `onSurfaceTextureAvailable` 与宿主的 `load` 谁先到都有可能，控制器自己会记着
     * （`detachSurface` 只暂停不释放）。没有控制器（这台宿主没配置预览）时两次调用都只是
     * 什么都不做 —— 与 [playVideoPreview] 同一条口径，不崩也不假装能播。
     *
     * 放在这里还有一层理由：`Surface` 是 Android 类型，而本类的 JVM 单测注入的是假控制器，
     * 所以这两次转发本身不需要（也无法）在 host 上构造 `Surface` 来测 —— 它们是两三行的
     * 纯转发，行为归 `RtpVideoPreviewController` 的单测。
     */
    fun attachVideoPreviewSurface(surface: Surface) {
        videoPreviewController?.attachSurface(surface)
    }

    /** 放开预览的 Surface，见 [attachVideoPreviewSurface]。 */
    fun detachVideoPreviewSurface() {
        videoPreviewController?.detachSurface()
    }

    /**
     * 关闭预览页：只暂停并清掉页面状态，**不释放**播放器 —— 与 [closePlayer] 同口径，
     * 播放器保持可复用（释放只发生在 [onCleared] 与换数据源时）。
     *
     * [videoPreviewAvailability] 故意不清：文件还在盘上，UI-01 的菜单项还应该显示。
     */
    fun closeVideoPreview() {
        videoPreviewJob?.cancel()
        videoPreviewJob = null
        videoPreviewController?.pause()
        _videoPreview.value = RtpVideoPreviewUiState()
    }

    /**
     * 预览可用性的判定本身：查盘 + 问解码器，再交给纯函数
     * [rtpVideoPreviewAvailability]（顺序由它钉住：先文件后解码器）。
     *
     * 文件检查与 `MediaCodecList` 都在 IO 上做：对一次点击来说两者都是阻塞调用。
     * 编码不是视频编码时不问解码器 —— 没有可问的 MIME（fail-closed 成 `NoExport`）。
     */
    private suspend fun computeVideoPreviewAvailability(
        stream: RtpStream,
        mp4Path: String,
        indexPath: String
    ): RtpVideoPreviewAvailability {
        val codec = rtpVideoCodecId(stream.codec)
        val mime = codec?.let { VideoMuxFormat.mimeFor(it) }
        return withContext(ioDispatcher) {
            val filesPresent = File(mp4Path).isFile && File(indexPath).isFile
            val decoderAvailable = if (filesPresent && mime != null) {
                videoDecoderProbe.hasDecoder(mime)
            } else {
                null
            }
            rtpVideoPreviewAvailability(
                mp4Path = mp4Path,
                indexPath = indexPath,
                filesPresent = filesPresent,
                codec = codec,
                decoderAvailable = decoderAvailable
            )
        }
    }

    /**
     * RTP5-KT-04：这条视频流能不能做音视频合成。**只发布结论**，不渲染 WAV、不编码
     * AAC、不写任何文件 —— 卡片要的是一个可以据以隐藏入口的信号，而一次能力询问不该
     * 有产生文件的副作用。
     *
     * [calls] 就是 M3 的结果（`VoipCallsUiState.Ready.calls`，即
     * `RtpCallLinker.link(...).calls`），由调用方交进来而不是本类自己去跑关联器：
     * 卡片说的是「依赖 M3」，不是「再实现一遍 M3」，而重新跑一次 SIP 关联既是第二份
     * 组合、也可能与用户看到的呼叫列表不是同一份快照。缺省的空表就是「调用方没有 M3
     * 的结果」，判定为 [RtpAvMuxAvailability.NoCall]（入口不显示）。
     *
     * 设备有没有 AAC 编码器要问一次 `MediaCodecList`（[aacEncoderProbe]），所以这里和
     * [refreshVideoPreviewAvailability] 一样起一个 Job —— 那一问是一小段 IO，不是一次
     * 渲染，更不是一次编码。
     */
    fun refreshAvMuxAvailability(
        videoStream: RtpStream,
        calls: List<VoipCall> = emptyList()
    ) {
        avMuxAvailabilityJob?.cancel()
        val job = runScope.launch(start = CoroutineStart.LAZY) {
            val encoderAvailable = withContext(ioDispatcher) { aacEncoderProbe.hasEncoder() }
            _avMuxAvailability.value =
                rtpAvMuxAvailability(videoStream, calls, encoderAvailable)
        }
        avMuxAvailabilityJob = job
        job.start()
    }

    /**
     * RTP5-KT-04：把这条视频流与它所属呼叫的音频合成一个 MP4，并写到 SAF 目的地。
     *
     * 三步，与 [RtpAvMuxStage] 一一对应：渲染 WAV 并用 `AacExporter` 把它编码成 `.m4a`
     * （[RtpAvMuxStage.AUDIO]）→ 原生的 `exportRtpVideo` 出 ES 与 `.vidx`
     * （[RtpAvMuxStage.VIDEO]）→ 两路交给 [avMuxer]（[RtpAvMuxStage.MUXING]）。对齐的
     * 两个基准就是这两条流自己的 `firstAbsEpochUs`，卡片的那一条规则在这里变成两个参数。
     *
     * 与 [exportVideo] 的分工相同：本函数只做「准备 + 发布状态」，真正的活在
     * [performAudioVideoExport] 里，结果落在 [avMuxState] 上。单条流而不是一个列表：
     * 音轨来自这条视频流**自己那个呼叫**的音频，多条流就是多个呼叫、多条音轨，那是
     * 另一张卡的事。
     *
     * 失败与取消都**不留半个 MP4**：本次请求自己的文件全在一个 request 目录里，任何
     * 一条不成功的路径都会把它整个删掉（封装器自己还会先删掉那个写了一半的 `.mp4`）。
     * 渲染好的 WAV 是另一回事 —— 它在 [prepareWavSources] 的缓存目录里，和播放器用的
     * 是同一个，删掉它只会让下一次导出白重渲染一遍。
     */
    fun exportAudioVideo(
        stream: RtpStream,
        calls: List<VoipCall> = emptyList(),
        destination: RtpExportDestination,
        startAtKeyframe: Boolean = true,
        dropCorrupt: Boolean = false,
        paramSets: VideoParamSets? = null
    ) {
        avMuxJob?.cancel()
        avMuxJob = null

        val scanResult = (_state.value as? RtpScanUiState.Done)?.result
        if (scanResult == null || !scanResult.isSuccess) {
            _avMuxState.value = RtpAvMuxUiState.Error(EXPORT_SCAN_REQUIRED_MESSAGE)
            return
        }
        val cache = mediaCache
        val root = cacheRoot ?: cache?.rootDir
        if (cache == null || root == null) {
            _avMuxState.value = RtpAvMuxUiState.Error(EXPORT_CACHE_UNAVAILABLE_MESSAGE)
            return
        }
        val sessionHandle = sessionCoordinator.state.value.sessionHandle
        if (sessionHandle == 0L) {
            _avMuxState.value = RtpAvMuxUiState.Error(EXPORT_NO_SESSION_MESSAGE)
            return
        }

        val job = runScope.launch(start = CoroutineStart.LAZY) {
            val encoderAvailable = withContext(ioDispatcher) { aacEncoderProbe.hasEncoder() }
            val availability = rtpAvMuxAvailability(stream, calls, encoderAvailable)
            _avMuxAvailability.value = availability
            if (availability !is RtpAvMuxAvailability.Ready) {
                _avMuxState.value =
                    RtpAvMuxUiState.Error(avMuxUnavailableMessage(availability))
                return@launch
            }
            // 与可用性判定读的是同一份输入、同一组纯函数，所以「菜单里能点」与
            // 「点下去用的就是那条流」不会出现两种答案。走到这里还拿不到音频流是
            // 不可能的（上面刚判过 Ready），但契约不许崩：报成「呼叫里没有音频」。
            val audioStream = linkedCallFor(stream.id, calls)?.let(::primaryAudioStream)
            if (audioStream == null) {
                _avMuxState.value =
                    RtpAvMuxUiState.Error(AV_MUX_NO_AUDIO_MESSAGE)
                return@launch
            }

            _avMuxState.value = RtpAvMuxUiState.Running(RtpAvMuxStage.AUDIO)
            val outcome = withContext(ioDispatcher) {
                try {
                    Result.success(
                        performAudioVideoExport(
                            videoStream = stream,
                            audioStream = audioStream,
                            scanGeneration = scanResult.scanGeneration,
                            sessionHandle = sessionHandle,
                            cache = cache,
                            cacheRoot = root,
                            startAtKeyframe = startAtKeyframe,
                            dropCorrupt = dropCorrupt,
                            paramSets = paramSets,
                            destination = destination
                        )
                    )
                } catch (cancelled: CancellationException) {
                    throw cancelled
                } catch (error: Throwable) {
                    Result.failure(error)
                }
            }
            _avMuxState.value = outcome.fold(
                onSuccess = { it },
                onFailure = { error ->
                    RtpAvMuxUiState.Error(error.message ?: AV_MUX_FAILED_MESSAGE)
                }
            )
        }
        avMuxJob = job
        job.start()
    }

    fun clearAvMuxState() {
        _avMuxState.value = RtpAvMuxUiState.Idle
    }

    /**
     * [RtpAvMuxAvailability] 的非 `Ready` 取值 → 一句给用户看的话。
     *
     * 每一条都是**不同**的拒绝理由，所以不许压成一句「不能合成」：用户看到的下一句话
     * 决定了他是去查呼叫、查音频流，还是去换台设备。`NoVideoExport` 复用 KT-02 那句
     * 「这条流没有视频导出」，它说的就是同一件事。
     */
    private fun avMuxUnavailableMessage(availability: RtpAvMuxAvailability): String =
        when (availability) {
            RtpAvMuxAvailability.NoCall -> AV_MUX_NO_CALL_MESSAGE
            is RtpAvMuxAvailability.CallHasNoAudio -> AV_MUX_NO_AUDIO_MESSAGE
            is RtpAvMuxAvailability.NoRenderedWav -> AV_MUX_NO_WAV_MESSAGE
            RtpAvMuxAvailability.NoVideoExport -> EXPORT_VIDEO_UNSUPPORTED_MESSAGE
            RtpAvMuxAvailability.NoAacEncoder -> AV_MUX_NO_ENCODER_MESSAGE
            is RtpAvMuxAvailability.Ready -> AV_MUX_FAILED_MESSAGE
        }

    /**
     * 一次音视频合成的核心。三步（见 [RtpAvMuxStage]）各自把产物写进**谁拥有谁负责删**
     * 的目录里：
     *
     *  - 音频 WAV 走 [prepareWavSources]，落在解码缓存的目录里（与播放器同一份，
     *    重复导出不重渲染，失败也不删 —— 它不是这次请求的产物）。
     *  - `.m4a` 与最终的 `.mp4` 落在本次请求**自己的** request 目录里；这一步之后
     *    任何一条不成功的路径都会把整个目录删掉，所以既不会有半个 MP4，也不会有
     *    一个没人认领的中间音频文件。
     *  - ES 与 `.vidx` 由 [exportVideoStreams] 写进它自己的 request 目录，失败时由它
     *    自己删（与 [exportVideoSource] 同一条口径，中间文件留在缓存里随缓存管理）。
     */
    private suspend fun performAudioVideoExport(
        videoStream: RtpStream,
        audioStream: RtpStream,
        scanGeneration: Long,
        sessionHandle: Long,
        cache: RtpMediaCache,
        cacheRoot: File,
        startAtKeyframe: Boolean,
        dropCorrupt: Boolean,
        paramSets: VideoParamSets?,
        destination: RtpExportDestination
    ): RtpAvMuxUiState.Finished {
        val wavFile = renderAudioWav(
            audioStream = audioStream,
            scanGeneration = scanGeneration,
            sessionHandle = sessionHandle,
            cache = cache,
            cacheRoot = cacheRoot
        )

        val requestDir = cache.dirFor(sessionHandle, nextMediaRequestId())
        var completed = false
        try {
            val m4aFile = File(requestDir, "${audioStream.id}.m4a")
            when (
                val encoded = aacExporter.export(wavFile, m4aFile) { done, total ->
                    _avMuxState.value = RtpAvMuxUiState.Running(
                        stage = RtpAvMuxStage.AUDIO,
                        done = done,
                        total = total
                    )
                }
            ) {
                is AacExportResult.Ok -> Unit
                // 设备没有编码器是 KT-04 的依赖，不是这次请求的错 —— 但它仍然以
                // 「这次导出失败」的面目出现（README §4.5.4，不静默换一个文件）。
                is AacExportResult.Unsupported -> error(encoded.reason)
                is AacExportResult.Failed -> error(encoded.message)
            }

            _avMuxState.value = RtpAvMuxUiState.Running(RtpAvMuxStage.VIDEO)
            val video = exportVideoStreams(
                stream = videoStream,
                scanGeneration = scanGeneration,
                sessionHandle = sessionHandle,
                cache = cache,
                cacheRoot = cacheRoot,
                startAtKeyframe = startAtKeyframe,
                dropCorrupt = dropCorrupt,
                paramSets = paramSets
            )

            val mp4File = File(
                requestDir,
                checkNotNull(rtpVideoMp4FileName(videoStream)) {
                    "Codec ${videoStream.codec} has no MP4 file name."
                }
            )
            _avMuxState.value = RtpAvMuxUiState.Running(RtpAvMuxStage.MUXING)
            val muxed = when (
                val result = avMuxer.mux(
                    esFile = video.esFile,
                    vidxFile = video.vidxFile,
                    codec = video.result.codec.ifBlank { video.codec },
                    width = video.result.width,
                    height = video.result.height,
                    paramSets = videoTrackParamSets(paramSets, video.result.csd),
                    audioFile = m4aFile,
                    outFile = mp4File,
                    // 卡片：「两路都以首包的 firstAbsEpochUs 为基准」。偏移量的
                    // 符号与负偏移的处理是 media/AvMuxPlan.kt 的事。
                    videoStartEpochUs = videoStream.firstAbsEpochUs,
                    audioStartEpochUs = audioStream.firstAbsEpochUs
                )
            ) {
                is AvMuxResult.Ok -> result
                is AvMuxResult.Failed -> error(result.message)
            }
            if (!isCacheFile(cache, cacheRoot, mp4File)) {
                error("The combined export was written outside the RTP media cache.")
            }
            destination.write(mp4File)
            completed = true
            return RtpAvMuxUiState.Finished(
                file = ExportResult(
                    filePath = mp4File.absolutePath,
                    displayName = destination.displayName,
                    mimeType = VideoMuxFormat.MIME_MP4
                ),
                videoFrames = muxed.videoFrames,
                audioSamples = muxed.audioSamples,
                droppedAudioSamples = muxed.droppedAudioSamples,
                audioOffsetUs = muxed.offsetUs
            )
        } finally {
            // 不成功（失败、取消、复制目的地时出错）就把本次请求的目录整个删掉：
            // 那里面有写了一半的 `.mp4`，也可能有已经编码好的 `.m4a`，两者都不该
            // 留下来让人以为「已经导出过了」。
            if (!completed) {
                requestDir.deleteRecursively()
            }
        }
    }

    /**
     * 音轨的 PCM：走 [prepareWavSources] 那条既有管线（会话级缓存、与播放器同一份
     * WAV），所以同一段音频不会为了合成再渲染一次。
     *
     * 时序参数用的是导出/播放的既有默认值（[RtpTimingMode.JITTER] +
     * [PLAYER_JITTER_MS]），与 `exportWav` / `shareWav` 的缺省完全一致 —— 于是
     * 「用户听到的那份 WAV」与「进了 MP4 的那份 WAV」是同一个文件，同一套抖动补齐。
     */
    private suspend fun renderAudioWav(
        audioStream: RtpStream,
        scanGeneration: Long,
        sessionHandle: Long,
        cache: RtpMediaCache,
        cacheRoot: File
    ): File {
        val preparation = prepareWavSources(
            streams = listOf(audioStream),
            scanGeneration = scanGeneration,
            sessionHandle = sessionHandle,
            cache = cache,
            cacheRoot = cacheRoot,
            timing = RtpTimingMode.JITTER,
            jitterMs = PLAYER_JITTER_MS
        )
        return preparation.files[audioStream.id]
            ?: error(preparation.failures.firstOrNull()?.message ?: EXPORT_DECODE_FAILED_MESSAGE)
    }

    /**
     * RTP5-KT-02：查一次本机有没有 H.265 解码器，结果发布在 [hevcDecoderAvailability]。
     *
     * 卡片要的是「提示但**仍然允许导出**」：本函数不返回值、不拦任何路径，导出流程
     * 只是在开始前顺手刷新一次这个信号。UI-01 也可以在打开导出对话框时单独调它。
     */
    fun refreshHevcDecoderAvailability() {
        runScope.launch {
            val found = withContext(ioDispatcher) {
                videoDecoderProbe.hasDecoder(VideoMuxFormat.MIME_H265)
            }
            _hevcDecoderAvailability.value = rtpVideoDecoderAvailability(found)
        }
    }

    /**
     * 「外部打开」用的候选 MIME 顺序：首选 MIME 在前。
     *
     * 裸流有两个候选（卡片第 1 条）：`video/h264` / `video/hevc` 在前，
     * `application/octet-stream` 在后 —— 后者就是「没有应用能处理这个 MIME」时的回退，
     * 判定完全交给 `ExternalPlayerLauncher.open` 的返回值，这里只排顺序。
     * MP4 只有一个 `video/mp4`：卡片没给容器格式留回退，而 `application/octet-stream`
     * 对 `.mp4` 也没有意义（系统本来就会按扩展名路由）。
     *
     * [RtpExportFormat.RAW] 的 MIME 被借来当那个回退值，这样「裸流的通用 MIME」在
     * 仓库里仍然只有一处定义。
     *
     * Kept internal so the fallback order is pinned by the JVM unit test.
     */
    internal fun videoOpenMimeTypes(
        codec: String,
        format: RtpVideoExportFormat
    ): List<String> = when (format) {
        RtpVideoExportFormat.MP4 -> listOf(VideoMuxFormat.MIME_MP4)
        RtpVideoExportFormat.RAW -> listOfNotNull(
            rtpVideoRawMimeType(codec),
            RtpExportFormat.RAW.mimeType
        )
    }

    /**
     * [RtpVideoOpenUiState.Ready] 的 MIME 顺序 → `ExternalPlayerLauncher` 的候选表。
     *
     * Kept internal so the JVM unit test can pin that the list is ordered (preferred
     * MIME first) and that every candidate points at the same file.
     */
    internal fun videoOpenCandidates(
        file: File,
        mimeTypes: List<String>
    ): List<ExternalPlayerLauncher.ExternalOpenCandidate> =
        mimeTypes.map { mimeType ->
            ExternalPlayerLauncher.ExternalOpenCandidate(file = file, mimeType = mimeType)
        }

    private fun startVideoExport(
        format: RtpVideoExportFormat,
        streams: List<RtpStream>,
        destinations: List<RtpExportDestination>?,
        startAtKeyframe: Boolean,
        dropCorrupt: Boolean,
        paramSets: VideoParamSets?,
        share: Boolean
    ) {
        val scanResult = (_state.value as? RtpScanUiState.Done)?.result
        if (scanResult == null || !scanResult.isSuccess) {
            _videoExportState.value = RtpVideoExportUiState.Error(EXPORT_SCAN_REQUIRED_MESSAGE)
            return
        }
        if (streams.isEmpty()) {
            _videoExportState.value = RtpVideoExportUiState.Error(EXPORT_NO_STREAMS_MESSAGE)
            return
        }
        val cache = mediaCache
        val root = cacheRoot ?: cache?.rootDir
        if (cache == null || root == null) {
            _videoExportState.value =
                RtpVideoExportUiState.Error(EXPORT_CACHE_UNAVAILABLE_MESSAGE)
            return
        }
        val sessionHandle = sessionCoordinator.state.value.sessionHandle
        if (sessionHandle == 0L) {
            _videoExportState.value = RtpVideoExportUiState.Error(EXPORT_NO_SESSION_MESSAGE)
            return
        }

        // 卡片：没有 HEVC 解码器时给提示，但导出照做。刷新这个信号与导出本身无关，
        // 所以它不参与下面的任何判断。
        streams.forEach(::refreshHevcDecoderAvailabilityFor)

        videoExportJob?.cancel()
        videoExportCancelRequested = false
        val job = runScope.launch(start = CoroutineStart.LAZY) {
            _videoExportState.value = RtpVideoExportUiState.Running(
                format = format,
                done = 0,
                total = streams.size,
                progress = RtpProgress(0, 100)
            )
            val summary = withContext(ioDispatcher) {
                performVideoExport(
                    format = format,
                    streams = streams,
                    destinations = destinations,
                    scanGeneration = scanResult.scanGeneration,
                    sessionHandle = sessionHandle,
                    cache = cache,
                    cacheRoot = root,
                    startAtKeyframe = startAtKeyframe,
                    dropCorrupt = dropCorrupt,
                    paramSets = paramSets,
                    share = share
                )
            }
            _videoExportState.value = RtpVideoExportUiState.Finished(
                summary = summary,
                shareResults = if (share) summary.files else emptyList()
            )
        }
        videoExportJob = job
        job.start()
    }

    private suspend fun performVideoExport(
        format: RtpVideoExportFormat,
        streams: List<RtpStream>,
        destinations: List<RtpExportDestination>?,
        scanGeneration: Long,
        sessionHandle: Long,
        cache: RtpMediaCache,
        cacheRoot: File,
        startAtKeyframe: Boolean,
        dropCorrupt: Boolean,
        paramSets: VideoParamSets?,
        share: Boolean
    ): RtpVideoExportSummary {
        val failures = mutableListOf<RtpExportFailure>()
        val files = mutableListOf<ExportResult>()
        val results = mutableMapOf<String, RtpVideoExportResult>()

        streams.forEachIndexed { index, stream ->
            try {
                check(stream.decodable == RtpDecodability.YES) {
                    "Stream ${stream.id} is not decodable."
                }
                val source = exportVideoSource(
                    stream = stream,
                    scanGeneration = scanGeneration,
                    sessionHandle = sessionHandle,
                    cache = cache,
                    cacheRoot = cacheRoot,
                    format = format,
                    startAtKeyframe = startAtKeyframe,
                    dropCorrupt = dropCorrupt,
                    paramSets = paramSets
                )
                results[stream.id] = source.result

                if (share) {
                    files += ExportResult(
                        filePath = source.file.absolutePath,
                        displayName = exportVideoDisplayName(stream, format),
                        mimeType = videoMimeType(stream, format)
                    )
                } else {
                    val destination = destinations?.getOrNull(index)
                        ?: error("No export destination was provided.")
                    destination.write(source.file)
                    files += ExportResult(
                        filePath = source.file.absolutePath,
                        displayName = destination.displayName,
                        mimeType = videoMimeType(stream, format)
                    )
                }
            } catch (cancelled: CancellationException) {
                throw cancelled
            } catch (error: Throwable) {
                failures += RtpExportFailure(
                    streamId = stream.id,
                    message = error.message ?: EXPORT_VIDEO_FAILED_MESSAGE
                )
            }
            val previous = _videoExportState.value as? RtpVideoExportUiState.Running
            _videoExportState.value = RtpVideoExportUiState.Running(
                format = format,
                done = index + 1,
                total = streams.size,
                phase = previous?.phase ?: RtpVideoExportPhase.EXTRACTING,
                progress = previous?.progress
            )
        }

        return RtpVideoExportSummary(
            format = format,
            files = files,
            failures = failures,
            results = results
        )
    }

    /** [exportVideoSource] 的两样产出：最终文件与原生结果（摘要要用的那些数字）。 */
    private data class RtpVideoSource(
        val file: File,
        val result: RtpVideoExportResult
    )

    /**
     * [exportVideoStreams] 的产出：ES、索引、它们所在的 request 目录、原生结果与
     * 归一化后的编码。
     *
     * [requestDir] 一并带出来，是因为「谁建的目录谁负责删」：KT-02 的 MP4 要写进它，
     * KT-04 的音视频合成也要知道 ES 在哪，而失败时的清理仍然归 [exportVideoStreams]。
     */
    private data class RtpVideoStreams(
        val codec: String,
        val esFile: File,
        val vidxFile: File,
        val requestDir: File,
        val result: RtpVideoExportResult
    )

    /**
     * 一次视频导出里**原生那一段**：一次 `exportRtpVideo`，加上「产物必须落在 RTP
     * 媒体缓存里」的校验与失败清理。KT-02 的 [exportVideoSource] 与 KT-04 的
     * [performAudioVideoExport] 共用它 —— 后者要的是 ES 与 `.vidx`，不要 MP4。
     *
     * 口径照 [exportContainerSource]：产物落在**本次调用自己的** request 目录里
     * （`cache.dirFor` 刚建出来的），失败时整个目录删掉。
     */
    /**
     * 把原生遍历或封装器报上来的进度写进当前那次操作。
     *
     * 导出和「外部播放」共用同一次 `exportRtpVideo`，所以两边各看各的状态：谁不在
     * 进行中就不动谁。回调来自原生线程，[StateFlow] 自己是线程安全的。
     */
    private fun publishVideoProgress(progress: RtpProgress) {
        val export = _videoExportState.value
        if (export is RtpVideoExportUiState.Running && export.progress != progress) {
            _videoExportState.value = export.copy(progress = progress)
        }
        val open = _videoOpenState.value
        if (open is RtpVideoOpenUiState.Preparing && open.progress != progress) {
            _videoOpenState.value = open.copy(progress = progress)
        }
    }

    private suspend fun exportVideoStreams(
        stream: RtpStream,
        scanGeneration: Long,
        sessionHandle: Long,
        cache: RtpMediaCache,
        cacheRoot: File,
        startAtKeyframe: Boolean,
        dropCorrupt: Boolean,
        paramSets: VideoParamSets?
    ): RtpVideoStreams {
        val codec = checkNotNull(rtpVideoCodecId(stream.codec)) {
            "Codec ${stream.codec} is not a video codec."
        }
        val requestDir = cache.dirFor(sessionHandle, nextMediaRequestId())
        val result = repository.exportVideo(
            scanGeneration = scanGeneration,
            streamId = stream.id,
            codec = codec,
            startAtKeyframe = startAtKeyframe,
            dropCorrupt = dropCorrupt,
            outDir = requestDir,
            paramSets = paramSets,
            onProgress = { progress ->
                publishVideoProgress(progress)
                !videoExportCancelRequested
            }
        )
        if (result.cancelled) {
            requestDir.deleteRecursively()
            error(EXPORT_VIDEO_CANCELLED_MESSAGE)
        }
        if (!result.isSuccess || !result.hasFiles) {
            // 失败时连文件名都没有（esPath 为空），只能按目录删 —— 原生层的
            // ScopedPathRemoval 已经删过一次，这里是同一条规则的兜底。
            requestDir.deleteRecursively()
            error(result.error.ifBlank { EXPORT_VIDEO_FAILED_MESSAGE })
        }
        val esFile = File(result.esPath)
        val vidxFile = File(result.indexPath)
        if (!isCacheFile(cache, cacheRoot, esFile) || !isCacheFile(cache, cacheRoot, vidxFile)) {
            requestDir.deleteRecursively()
            error("The video export was written outside the RTP media cache.")
        }
        return RtpVideoStreams(
            codec = codec,
            esFile = esFile,
            vidxFile = vidxFile,
            requestDir = requestDir,
            result = result
        )
    }

    /**
     * 一次视频导出的核心，口径照 [exportContainerSource]：所有产物都落在**本次调用
     * 自己的** request 目录里（`cache.dirFor` 刚建出来的），失败时整个目录删掉。
     *
     * 裸流：原生产物就是最终产物（`<streamId>.h264`），原样发布；MP4：把 ES 与 `.vidx`
     * 交给 KT-01 的封装器，写出的 `.mp4` 才是最终产物 —— 原生那两个中间文件留在同一个
     * request 目录里，随导出结果一起被缓存管理，不额外删（`exportRtpVideo` 的产物路径
     * 是它自己给的，删错会伤到别的导出）。
     */
    private suspend fun exportVideoSource(
        stream: RtpStream,
        scanGeneration: Long,
        sessionHandle: Long,
        cache: RtpMediaCache,
        cacheRoot: File,
        format: RtpVideoExportFormat,
        startAtKeyframe: Boolean,
        dropCorrupt: Boolean,
        paramSets: VideoParamSets?
    ): RtpVideoSource {
        val streams = exportVideoStreams(
            stream = stream,
            scanGeneration = scanGeneration,
            sessionHandle = sessionHandle,
            cache = cache,
            cacheRoot = cacheRoot,
            startAtKeyframe = startAtKeyframe,
            dropCorrupt = dropCorrupt,
            paramSets = paramSets
        )

        return when (format) {
            RtpVideoExportFormat.RAW -> RtpVideoSource(streams.esFile, streams.result)

            RtpVideoExportFormat.MP4 -> {
                val mp4File = File(
                    streams.requestDir,
                    checkNotNull(rtpVideoMp4FileName(stream)) {
                        "Codec ${stream.codec} has no MP4 file name."
                    }
                )
                val extracting = _videoExportState.value as? RtpVideoExportUiState.Running
                if (extracting != null) {
                    _videoExportState.value = extracting.copy(
                        phase = RtpVideoExportPhase.MUXING,
                        progress = null
                    )
                }
                when (
                    val muxed = videoMuxer.mux(
                        esFile = streams.esFile,
                        vidxFile = streams.vidxFile,
                        codec = streams.result.codec.ifBlank { streams.codec },
                        width = streams.result.width,
                        height = streams.result.height,
                        paramSets = videoTrackParamSets(paramSets, streams.result.csd),
                        outFile = mp4File,
                        onProgress = { done, total ->
                            publishVideoProgress(RtpProgress(done, total))
                        }
                    )
                ) {
                    is VideoMuxResult.Ok -> RtpVideoSource(mp4File, streams.result)
                    is VideoMuxResult.Failed -> {
                        streams.requestDir.deleteRecursively()
                        error(muxed.message)
                    }
                }
            }
        }
    }

    /**
     * 导出结果里的 MIME。MP4 取 KT-01 的 [VideoMuxFormat.MIME_MP4]，别处不再写一遍
     * `video/mp4`；裸流的 MIME 由编码决定（`video/h264` / `video/hevc`，卡片第 1 条），
     * 兜底用 `application/octet-stream`（与 [RtpExportFormat.RAW] 同值 —— 这条兜底在
     * 这里走不到，编码不是视频的流在 [exportVideoSource] 就失败了）。
     */
    private fun videoMimeType(stream: RtpStream, format: RtpVideoExportFormat): String =
        when (format) {
            RtpVideoExportFormat.MP4 -> VideoMuxFormat.MIME_MP4
            RtpVideoExportFormat.RAW ->
                rtpVideoRawMimeType(stream.codec) ?: RtpExportFormat.RAW.mimeType
        }

    private fun exportVideoDisplayName(
        stream: RtpStream,
        format: RtpVideoExportFormat
    ): String = rtpVideoFileName(stream, format) ?: when (format) {
        RtpVideoExportFormat.MP4 -> "${stream.id}.mp4"
        RtpVideoExportFormat.RAW -> "${stream.id}.h264"
    }

    /**
     * 只有这条流真的是 H.265 才去探 HEVC 解码器：卡片点名的是 HEVC，H.264 的解码器
     * 不在本卡的范围里（探到了也没有提示可发），少一次 `MediaCodecList` 构造。
     */
    private fun refreshHevcDecoderAvailabilityFor(stream: RtpStream) {
        if (rtpVideoCodecId(stream.codec) == VIDEO_CODEC_H265) {
            refreshHevcDecoderAvailability()
        }
    }

    private fun decodePlayer() {
        val current = _playerState.value
        val selectedStreamId = current.selectedStreamId ?: return
        val streamIds = current.streams.map { it.id }
        if (streamIds.isEmpty()) return

        val scanResult = (_state.value as? RtpScanUiState.Done)?.result
        if (scanResult == null || !scanResult.isSuccess) {
            _playerState.value = current.copy(
                status = RtpPlayerDecodeStatus.ERROR,
                progress = null,
                errorMessage = PLAYER_SCAN_REQUIRED_MESSAGE
            )
            return
        }
        val cache = mediaCache
        if (cache == null) {
            _playerState.value = current.copy(
                status = RtpPlayerDecodeStatus.ERROR,
                progress = null,
                errorMessage = PLAYER_CACHE_UNAVAILABLE_MESSAGE
            )
            return
        }
        val session = sessionCoordinator.state.value
        if (!session.hasSession) {
            _playerState.value = current.copy(
                status = RtpPlayerDecodeStatus.ERROR,
                progress = null,
                errorMessage = PLAYER_NO_SESSION_MESSAGE
            )
            return
        }

        playerDecodeRequestId += 1
        playerDecodeJob?.cancel()
        audioPlayerController?.pause()
        sessionCoordinator.cancelLongRunningOperations()
        deletePlayerDecodeRequest()

        val requestId = playerDecodeRequestId
        val mediaRequestId = nextMediaRequestId()
        val outDir = runCatching {
            cache.dirFor(session.sessionHandle, mediaRequestId)
        }.getOrElse { error ->
            _playerState.value = current.copy(
                status = RtpPlayerDecodeStatus.ERROR,
                progress = null,
                errorMessage = error.message ?: PLAYER_DECODE_FAILED_MESSAGE
            )
            return
        }
        playerDecodeSessionHandle = session.sessionHandle
        playerDecodeMediaRequestId = mediaRequestId
        val expectedSession = session.token

        _playerState.value = current.copy(
            status = RtpPlayerDecodeStatus.DECODING,
            progress = RtpProgress(0, 100),
            decodedItems = emptyList(),
            unsupported = emptyList(),
            errorMessage = null
        )

        val job = runScope.launch(start = CoroutineStart.LAZY) {
            val result = try {
                withContext(ioDispatcher) {
                    repository.decodeAudio(
                        request = RtpDecodeRequest(
                            scanGeneration = scanResult.scanGeneration,
                            streamIds = streamIds,
                            timing = current.timing,
                            jitterMs = PLAYER_JITTER_MS,
                            // RTP4-KT-03：路由表要按编码取，之前没有任何调用点填它，
                            // MEDIACODEC 那一段（AMR / AMR-WB / Opus）等于死代码。
                            streamCodecs = current.streams.associate { it.id to it.codec }
                        ),
                        outDir = outDir,
                        onProgress = { progress ->
                            val keep = requestId == playerDecodeRequestId &&
                                sessionCoordinator.isCurrent(expectedSession)
                            if (keep) {
                                val latest = _playerState.value
                                if (latest.selectedStreamId == selectedStreamId) {
                                    _playerState.value = latest.copy(progress = progress)
                                }
                            }
                            keep
                        }
                    )
                }
            } catch (cancelled: CancellationException) {
                throw cancelled
            } catch (error: Throwable) {
                if (
                    requestId == playerDecodeRequestId &&
                    sessionCoordinator.isCurrent(expectedSession)
                ) {
                    _playerState.value = _playerState.value.copy(
                        status = RtpPlayerDecodeStatus.ERROR,
                        progress = null,
                        errorMessage = error.message ?: PLAYER_DECODE_FAILED_MESSAGE
                    )
                }
                return@launch
            }

            if (
                requestId != playerDecodeRequestId ||
                !sessionCoordinator.isCurrent(expectedSession)
            ) {
                runCatching { cache.deleteRequest(session.sessionHandle, mediaRequestId) }
                return@launch
            }
            publishPlayerDecodeResult(
                result = result,
                sessionHandle = session.sessionHandle
            )
        }
        playerDecodeJob = job
        job.start()
    }

    private fun publishPlayerDecodeResult(
        result: RtpDecodeResult,
        sessionHandle: Long
    ) {
        val current = _playerState.value
        val streamIds = current.streams.mapTo(mutableSetOf()) { it.id }
        val items = result.items.filter { it.streamId in streamIds }
        val unsupported = result.unsupported.filter { it.streamId in streamIds }
        val selectedStreamId = current.selectedStreamId

        rememberDecodedWavFiles(items, sessionHandle, current.timing)

        val selectedItem = items.firstOrNull { it.streamId == selectedStreamId }
        when {
            result.cancelled -> {
                _playerState.value = current.copy(
                    status = RtpPlayerDecodeStatus.CANCELLED,
                    progress = null,
                    decodedItems = items,
                    unsupported = unsupported,
                    errorMessage = null
                )
            }

            result.error.isNotEmpty() -> {
                _playerState.value = current.copy(
                    status = RtpPlayerDecodeStatus.ERROR,
                    progress = null,
                    decodedItems = items,
                    unsupported = unsupported,
                    errorMessage = result.error
                )
            }

            selectedItem != null -> {
                loadPlayerSource(selectedItem)
                _playerState.value = current.copy(
                    status = RtpPlayerDecodeStatus.READY,
                    progress = null,
                    decodedItems = items,
                    unsupported = unsupported,
                    errorMessage = null
                )
            }

            unsupported.any { it.streamId == selectedStreamId } -> {
                _playerState.value = current.copy(
                    status = RtpPlayerDecodeStatus.READY,
                    progress = null,
                    decodedItems = items,
                    unsupported = unsupported,
                    errorMessage = null
                )
            }

            else -> {
                _playerState.value = current.copy(
                    status = RtpPlayerDecodeStatus.ERROR,
                    progress = null,
                    decodedItems = items,
                    unsupported = unsupported,
                    errorMessage = PLAYER_DECODE_MISSING_MESSAGE
                )
            }
        }
    }

    private fun rememberDecodedWavFiles(
        items: List<RtpDecodedItem>,
        sessionHandle: Long,
        timing: RtpTimingMode
    ) {
        val cache = mediaCache ?: return
        val root = cacheRoot ?: cache.rootDir
        items.forEach { item ->
            val source = item.wavPath.takeIf(String::isNotBlank)?.let(::File) ?: return@forEach
            if (isCacheFile(cache, root, source)) {
                decodedWavFiles[
                    DecodedWavKey(
                        sessionHandle = sessionHandle,
                        streamId = item.streamId,
                        timing = timing,
                        jitterMs = PLAYER_JITTER_MS
                    )
                ] = source
            }
        }
    }

    private fun loadPlayerSource(item: RtpDecodedItem) {
        val path = item.wavPath.takeIf(String::isNotBlank) ?: return
        audioPlayerController?.load(path, autoPlay = playerAutoPlay)
    }

    private fun deletePlayerDecodeRequest() {
        val sessionHandle = playerDecodeSessionHandle
        val requestId = playerDecodeMediaRequestId
        playerDecodeSessionHandle = null
        playerDecodeMediaRequestId = null
        if (sessionHandle != null && requestId != null) {
            mediaCache?.deleteRequest(sessionHandle, requestId)
        }
    }

    /**
     * 会话语义上的失效：取消在途扫描、清掉会话级结果与覆盖表、回到 [RtpScanUiState.Idle]。
     *
     * 「已选/高亮流」的记录在 KT-02 里还不存在（那张卡的 UI 才有），所以这里只清理覆盖表。
     */
    private fun resetForInvalidation() {
        scanJob?.cancel()
        exportJob?.cancel()
        externalOpenJob?.cancel()
        externalOpenJob = null
        videoExportJob?.cancel()
        videoExportJob = null
        videoOpenJob?.cancel()
        videoOpenJob = null
        videoPreviewJob?.cancel()
        videoPreviewJob = null
        videoPreviewAvailabilityJob?.cancel()
        videoPreviewAvailabilityJob = null
        avMuxJob?.cancel()
        avMuxJob = null
        avMuxAvailabilityJob?.cancel()
        avMuxAvailabilityJob = null
        playerDecodeRequestId += 1
        playerDecodeJob?.cancel()
        playerDecodeJob = null
        deletePlayerDecodeRequest()
        sessionCoordinator.cancelLongRunningOperations()
        _state.value = RtpScanUiState.Idle
        _exportState.value = RtpExportUiState.Idle
        _externalOpenState.value = RtpExternalOpenUiState.Idle
        _videoExportState.value = RtpVideoExportUiState.Idle
        _videoOpenState.value = RtpVideoOpenUiState.Idle
        // 预览的 MP4 就在**本会话**的缓存目录里，会话一变（关文件、重开、解码配置变）它
        // 已经不存在了，所以预览页与可用性一起退回初始值 —— 与上面几个状态同一条规则。
        videoPreviewController?.pause()
        _videoPreview.value = RtpVideoPreviewUiState()
        _videoPreviewAvailability.value = RtpVideoPreviewAvailability.NoExport
        // RTP5-KT-04：合成的产物与它的可用性同理 —— 音频 WAV 与 MP4 都在**本会话**的
        // 缓存目录里，会话一变就都不在了，所以两者一起退回初始值（没有 M3 结果 ⇒ 不显示）。
        _avMuxState.value = RtpAvMuxUiState.Idle
        _avMuxAvailability.value = RtpAvMuxAvailability.NoCall
        // `hevcDecoderAvailability` 故意**不**在这里清空：它说的是「这台设备有没有
        // HEVC 解码器」，换一个抓包文件不会换设备，把它退回 UNKNOWN 只会让提示闪一下。
        // `aacEncoderProbe` 的答案同理，它根本没有被记住（每次可用性询问现问一次）。
        audioPlayerController?.pause()
        _playerState.value = RtpPlayerUiState()
        _overrides.value = emptyList()
        decodedWavFiles.clear()
        mediaRequestId = 0L
        highlightStream(null)
    }

    override fun onCleared() {
        exportJob?.cancel()
        externalOpenJob?.cancel()
        videoExportJob?.cancel()
        videoOpenJob?.cancel()
        videoPreviewJob?.cancel()
        videoPreviewAvailabilityJob?.cancel()
        avMuxJob?.cancel()
        avMuxAvailabilityJob?.cancel()
        videoMuxer.cancel()
        // RTP5-KT-04：三次等待各自有自己的取消开关 —— 原生的导出归
        // `cancelLongRunningOperations`（上面几个 Job 的取消路径里已经有它），封装器与
        // 编码器这两个 `android.media.*` 的循环不归它管，必须各自叫停。
        avMuxer.cancel()
        aacExporter.cancel()
        playerDecodeJob?.cancel()
        audioPlayerController?.release()
        videoPreviewController?.release()
        super.onCleared()
    }

    private fun startExport(
        kind: RtpExportKind,
        streams: List<RtpStream>,
        destinations: List<RtpExportDestination>?,
        timing: RtpTimingMode = RtpTimingMode.JITTER,
        jitterMs: Int = 50,
        order: RtpRawOrder = RtpRawOrder.SEQ,
        share: Boolean
    ) {
        val scanResult = (_state.value as? RtpScanUiState.Done)?.result
        if (scanResult == null || !scanResult.isSuccess) {
            _exportState.value = RtpExportUiState.Error(EXPORT_SCAN_REQUIRED_MESSAGE)
            return
        }
        if (streams.isEmpty()) {
            _exportState.value = RtpExportUiState.Error(EXPORT_NO_STREAMS_MESSAGE)
            return
        }
        val cache = mediaCache
        val root = cacheRoot ?: cache?.rootDir
        if (cache == null || root == null) {
            _exportState.value = RtpExportUiState.Error(EXPORT_CACHE_UNAVAILABLE_MESSAGE)
            return
        }
        val sessionHandle = sessionCoordinator.state.value.sessionHandle
        if (sessionHandle == 0L) {
            _exportState.value = RtpExportUiState.Error(EXPORT_NO_SESSION_MESSAGE)
            return
        }

        exportJob?.cancel()
        audioExportCancelRequested = false
        val job = runScope.launch(start = CoroutineStart.LAZY) {
            _exportState.value = RtpExportUiState.Running(kind, 0, streams.size)
            val summary = withContext(ioDispatcher) {
                performExport(
                    kind = kind,
                    streams = streams,
                    destinations = destinations,
                    scanGeneration = scanResult.scanGeneration,
                    sessionHandle = sessionHandle,
                    cache = cache,
                    cacheRoot = root,
                    timing = timing,
                    jitterMs = jitterMs,
                    order = order,
                    share = share
                )
            }
            _exportState.value = RtpExportUiState.Finished(
                summary = summary,
                shareResults = if (share) summary.files else emptyList()
            )
        }
        exportJob = job
        job.start()
    }

    private fun performExport(
        kind: RtpExportKind,
        streams: List<RtpStream>,
        destinations: List<RtpExportDestination>?,
        scanGeneration: Long,
        sessionHandle: Long,
        cache: RtpMediaCache,
        cacheRoot: File,
        timing: RtpTimingMode,
        jitterMs: Int,
        order: RtpRawOrder,
        share: Boolean
    ): RtpExportSummary {
        val failures = mutableListOf<RtpExportFailure>()
        val files = mutableListOf<ExportResult>()
        val wavSources = if (kind == RtpExportKind.WAV) {
            prepareWavSources(
                streams = streams,
                scanGeneration = scanGeneration,
                sessionHandle = sessionHandle,
                cache = cache,
                cacheRoot = cacheRoot,
                timing = timing,
                jitterMs = jitterMs
            ).also { preparation -> failures += preparation.failures }
        } else {
            null
        }
        val failedStreamIds = failures.mapTo(mutableSetOf()) { it.streamId }

        streams.forEachIndexed { index, stream ->
            if (stream.id in failedStreamIds) {
                _exportState.value = RtpExportUiState.Running(
                    kind = kind,
                    done = index + 1,
                    total = streams.size
                )
                return@forEachIndexed
            }
            try {
                check(stream.decodable == RtpDecodability.YES) {
                    "Stream ${stream.id} is not decodable."
                }
                val source = when (kind) {
                    RtpExportKind.WAV -> {
                        val prepared = wavSources?.files?.get(stream.id)
                        checkNotNull(prepared) { "No decoded WAV is available." }
                    }

                    RtpExportKind.RAW -> exportRawSource(
                        stream = stream,
                        scanGeneration = scanGeneration,
                        sessionHandle = sessionHandle,
                        cache = cache,
                        cacheRoot = cacheRoot,
                        order = order
                    )

                    RtpExportKind.AMR,
                    RtpExportKind.AWB,
                    RtpExportKind.OPUS -> exportContainerSource(
                        stream = stream,
                        scanGeneration = scanGeneration,
                        sessionHandle = sessionHandle,
                        cache = cache,
                        cacheRoot = cacheRoot,
                        format = kind.format
                    )
                }
                check(cache.contains(source) && source.isFile) {
                    "The exported source is outside the RTP media cache."
                }

                // RTP4-KT-03：MIME 集中在 RtpExportFormat 上（卡片固定的五个值），
                // WAV/裸流的取值与 RTP2-KT-04 完全一致。
                val mimeType = kind.format.mimeType
                if (share) {
                    files += ExportResult(
                        filePath = source.absolutePath,
                        displayName = exportDisplayName(stream, kind),
                        mimeType = mimeType
                    )
                } else {
                    val destination = destinations?.getOrNull(index)
                        ?: error("No export destination was provided.")
                    destination.write(source)
                    files += ExportResult(
                        filePath = source.absolutePath,
                        displayName = destination.displayName,
                        mimeType = mimeType
                    )
                }
            } catch (cancelled: CancellationException) {
                throw cancelled
            } catch (error: Throwable) {
                failedStreamIds += stream.id
                failures += RtpExportFailure(
                    streamId = stream.id,
                    message = error.message ?: EXPORT_FAILED_MESSAGE
                )
            }
            _exportState.value = RtpExportUiState.Running(
                kind = kind,
                done = index + 1,
                total = streams.size
            )
        }

        return RtpExportSummary(kind = kind, files = files, failures = failures)
    }

    private fun prepareWavSources(
        streams: List<RtpStream>,
        scanGeneration: Long,
        sessionHandle: Long,
        cache: RtpMediaCache,
        cacheRoot: File,
        timing: RtpTimingMode,
        jitterMs: Int
    ): WavPreparation {
        val files = mutableMapOf<String, File>()
        val failures = mutableListOf<RtpExportFailure>()
        streams.forEach { stream ->
            if (stream.decodable != RtpDecodability.YES) return@forEach
            val key = DecodedWavKey(sessionHandle, stream.id, timing, jitterMs)
            val existing = decodedWavFiles[key]
            if (existing != null && isCacheFile(cache, cacheRoot, existing)) {
                files[stream.id] = existing
                return@forEach
            }
            decodedWavFiles.remove(key)

            val result = try {
                val outDir = cache.dirFor(sessionHandle, nextMediaRequestId())
                repository.decodeAudio(
                    request = RtpDecodeRequest(
                        scanGeneration = scanGeneration,
                        streamIds = listOf(stream.id),
                        timing = timing,
                        jitterMs = jitterMs,
                        // RTP4-KT-03：导出 WAV 与播放走同一条路由，编码必须一起送进去。
                        streamCodecs = mapOf(stream.id to stream.codec)
                    ),
                    outDir = outDir,
                    onProgress = { progress ->
                        val current = _exportState.value
                        if (current is RtpExportUiState.Running && current.progress != progress) {
                            _exportState.value = current.copy(progress = progress)
                        }
                        !audioExportCancelRequested
                    }
                )
            } catch (cancelled: CancellationException) {
                throw cancelled
            } catch (error: Throwable) {
                failures += RtpExportFailure(
                    stream.id,
                    error.message ?: EXPORT_DECODE_FAILED_MESSAGE
                )
                return@forEach
            }

            val item = result.items.firstOrNull { it.streamId == stream.id }
            val source = item?.wavPath
                ?.takeIf(String::isNotBlank)
                ?.let(::File)
            val unsupported = result.unsupported.firstOrNull { it.streamId == stream.id }
            when {
                source != null && isCacheFile(cache, cacheRoot, source) -> {
                    decodedWavFiles[
                        DecodedWavKey(sessionHandle, stream.id, timing, jitterMs)
                    ] = source
                    files[stream.id] = source
                }

                result.cancelled -> {
                    failures += RtpExportFailure(stream.id, EXPORT_DECODE_CANCELLED_MESSAGE)
                }

                result.error.isNotEmpty() -> {
                    failures += RtpExportFailure(stream.id, result.error)
                }

                unsupported != null -> {
                    failures += RtpExportFailure(stream.id, unsupported.reason)
                }

                else -> {
                    failures += RtpExportFailure(
                        stream.id,
                        EXPORT_DECODE_MISSING_MESSAGE
                    )
                }
            }
        }
        return WavPreparation(files, failures)
    }

    private fun exportRawSource(
        stream: RtpStream,
        scanGeneration: Long,
        sessionHandle: Long,
        cache: RtpMediaCache,
        cacheRoot: File,
        order: RtpRawOrder
    ): File {
        val fileName = checkNotNull(rtpRawFileName(stream)) {
            "Codec ${stream.codec} does not support raw payload export."
        }
        val requestDir = cache.dirFor(sessionHandle, nextMediaRequestId())
        val output = File(requestDir, "${stream.id}-$fileName")
        val result = repository.exportRaw(
            scanGeneration = scanGeneration,
            streamId = stream.id,
            order = order,
            outFile = output
        )
        if (result.error.isNotEmpty()) {
            output.delete()
            error(result.error)
        }
        if (!isCacheFile(cache, cacheRoot, output)) {
            output.delete()
            error("The raw export was written outside the RTP media cache.")
        }
        return output
    }

    private fun isCacheFile(cache: RtpMediaCache, cacheRoot: File, file: File): Boolean =
        file.isFile &&
            runCatching {
                val root = cacheRoot.canonicalFile
                val candidate = file.canonicalFile
                cache.contains(candidate) &&
                    (candidate == root || candidate.startsWith(root))
            }.getOrDefault(false)

    /**
     * 容器导出（RTP4-KT-03）：写入**同一个 RTP media cache 的 request 目录**
     * （口径照 [exportRawSource]），文件名与 [rtpWavFileName]/[rtpRawFileName] 同形状。
     *
     * 原生层的 `exportRtpContainer` 已经保证「写失败时只删半成品容器」；Kotlin 侧
     * 负责另外几种「留下垃圾」的情况：请求被取消、写失败时来不及删的半成品、以及产出
     * 落在缓存根之外 —— 一律删掉本次请求**自己的**那个 request 目录（是本次调用刚
     * `dirFor` 出来的，与 `decodeAudio` 的失败清理同一口径，删不到别人的东西）。
     */
    private fun exportContainerSource(
        stream: RtpStream,
        scanGeneration: Long,
        sessionHandle: Long,
        cache: RtpMediaCache,
        cacheRoot: File,
        format: RtpExportFormat
    ): File {
        val supported = checkNotNull(RtpCodecCatalog.containerFormat(stream.codec)) {
            "Codec ${stream.codec} does not support container export."
        }
        check(supported == format) {
            "Codec ${stream.codec} is not exported as ${format.name}."
        }
        val nativeFormat = checkNotNull(format.containerFormat) {
            "${format.name} is not a native container format."
        }
        val requestDir = cache.dirFor(sessionHandle, nextMediaRequestId())
        val result = repository.exportContainer(
            scanGeneration = scanGeneration,
            streamId = stream.id,
            format = nativeFormat,
            outDir = requestDir
        )
        val output = result.path.takeIf(String::isNotBlank)?.let(::File)
        if (result.cancelled) {
            requestDir.deleteRecursively()
            error(EXPORT_CONTAINER_CANCELLED_MESSAGE)
        }
        if (!result.isSuccess || output == null) {
            // 原生层的半成品清理不能依赖：结果里 path 为空时这里连文件名都不知道，
            // 只能按 request 目录删。
            requestDir.deleteRecursively()
            error(result.error.ifBlank { EXPORT_CONTAINER_FAILED_MESSAGE })
        }
        if (!isCacheFile(cache, cacheRoot, output)) {
            output.delete()
            requestDir.deleteRecursively()
            error("The container export was written outside the RTP media cache.")
        }
        return output
    }

    private fun exportDisplayName(stream: RtpStream, kind: RtpExportKind): String =
        when (kind) {
            RtpExportKind.WAV -> rtpWavFileName(stream)
            RtpExportKind.RAW -> rtpRawFileName(stream) ?: "${stream.id}.raw"
            RtpExportKind.AMR,
            RtpExportKind.AWB,
            RtpExportKind.OPUS ->
                rtpContainerFileName(stream, kind.format) ?: "${stream.id}.bin"
        }

    private fun nextMediaRequestId(): Long = ++mediaRequestId

    private data class SessionKey(
        val sessionHandle: Long,
        val sessionGeneration: Long,
        val analysisConfigVersion: Int
    )

    private data class DecodedWavKey(
        val sessionHandle: Long,
        val streamId: String,
        val timing: RtpTimingMode,
        val jitterMs: Int
    )

    private data class WavPreparation(
        val files: Map<String, File>,
        val failures: List<RtpExportFailure>
    )

    private companion object {
        const val SCAN_FAILED_MESSAGE = "RTP scan failed."
        const val OVERRIDE_FAILED_MESSAGE = "Unable to apply RTP payload overrides."
        const val HIGHLIGHT_DURATION_MS = 5_000L
        const val EXPORT_SCAN_REQUIRED_MESSAGE = "Scan RTP streams before exporting."
        const val EXPORT_NO_STREAMS_MESSAGE = "Select at least one RTP stream to export."
        const val EXPORT_CACHE_UNAVAILABLE_MESSAGE = "RTP media cache is not configured."
        const val EXPORT_NO_SESSION_MESSAGE = "No capture is open."
        const val EXPORT_FAILED_MESSAGE = "RTP export failed."
        const val EXPORT_DECODE_FAILED_MESSAGE = "Unable to render RTP audio."
        const val EXPORT_DECODE_CANCELLED_MESSAGE = "RTP audio rendering was cancelled."
        const val EXPORT_DECODE_MISSING_MESSAGE = "The renderer did not produce a WAV file."
        const val EXPORT_CONTAINER_FAILED_MESSAGE = "Unable to export the RTP container."
        const val EXPORT_CONTAINER_CANCELLED_MESSAGE = "The RTP container export was cancelled."
        const val EXPORT_VIDEO_FAILED_MESSAGE = "Unable to export the RTP video."
        const val EXPORT_VIDEO_CANCELLED_MESSAGE = "The RTP video export was cancelled."
        const val EXPORT_VIDEO_UNSUPPORTED_MESSAGE =
            "This stream has no video export. Scan a stream whose codec is H.264 or H.265."
        const val PREVIEW_MISSING_MESSAGE =
            "There is no exported MP4 to preview."
        const val PREVIEW_NO_DECODER_MESSAGE =
            "This device has no decoder for this video codec."
        const val PREVIEW_INDEX_FAILED_MESSAGE =
            "The video index could not be read."

        /**
         * RTP5-KT-04：合成的五条拒绝理由，一条一句 —— 用户看到的下一句话决定了他去
         * 查呼叫、查音频流，还是去换台设备，压成一句「不能合成」等于什么都没说。
         * `NoVideoExport` 那一档复用上面 KT-02 的同义句。
         */
        const val AV_MUX_NO_CALL_MESSAGE =
            "This stream is not linked to a call, so there is no audio to combine."
        const val AV_MUX_NO_AUDIO_MESSAGE =
            "The call this stream belongs to has no audio stream."
        const val AV_MUX_NO_WAV_MESSAGE =
            "The call's audio stream cannot be rendered to a WAV file."
        const val AV_MUX_NO_ENCODER_MESSAGE =
            "This device has no AAC encoder, so the audio cannot be combined."
        const val AV_MUX_FAILED_MESSAGE = "Unable to mux the audio and video."

        /** 规范 ID 的 H.265（README §4.3）；只有它需要「没有解码器」的提示。 */
        const val VIDEO_CODEC_H265 = "H265"

        const val PLAYER_JITTER_MS = 50
        const val PLAYER_SCAN_REQUIRED_MESSAGE = "Scan RTP streams before playing audio."
        const val PLAYER_CACHE_UNAVAILABLE_MESSAGE = "RTP media cache is not configured."
        const val PLAYER_NO_SESSION_MESSAGE = "No capture is open."
        const val PLAYER_DECODE_FAILED_MESSAGE = "Unable to render RTP audio."
        const val PLAYER_DECODE_MISSING_MESSAGE = "The renderer did not produce audio for this stream."
    }
}
