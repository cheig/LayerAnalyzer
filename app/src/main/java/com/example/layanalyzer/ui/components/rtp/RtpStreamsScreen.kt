// Copyright (c) 2026 cheig
// LayerAnalyzer - https://github.com/cheig/LayerAnalyzer
// Licensed under GNU GPL version 3; see LICENSE.

package com.example.layanalyzer.ui.components.rtp

import android.content.res.Configuration
import android.net.Uri
import androidx.activity.compose.BackHandler
import androidx.compose.foundation.ExperimentalFoundationApi
import androidx.compose.foundation.border
import androidx.compose.foundation.clickable
import androidx.compose.foundation.combinedClickable
import androidx.compose.foundation.horizontalScroll
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.ColumnScope
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.widthIn
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.foundation.lazy.rememberLazyListState
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.automirrored.filled.ArrowBack
import androidx.compose.material.icons.filled.Call
import androidx.compose.material.icons.filled.Close
import androidx.compose.material.icons.filled.Download
import androidx.compose.material.icons.filled.MoreVert
import androidx.compose.material.icons.filled.Movie
import androidx.compose.material.icons.filled.PlayArrow
import androidx.compose.material.icons.filled.Refresh
import androidx.compose.material3.AlertDialog
import androidx.compose.material3.Button
import androidx.compose.material3.Card
import androidx.compose.material3.Checkbox
import androidx.compose.material3.DropdownMenu
import androidx.compose.material3.DropdownMenuItem
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.FilterChip
import androidx.compose.material3.HorizontalDivider
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.LinearProgressIndicator
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.Scaffold
import androidx.compose.material3.SnackbarHost
import androidx.compose.material3.SnackbarHostState
import androidx.compose.material3.Surface
import androidx.compose.material3.Switch
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.material3.TopAppBar
import androidx.compose.runtime.Composable
import androidx.compose.runtime.DisposableEffect
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.rememberCoroutineScope
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.graphics.vector.ImageVector
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.tooling.preview.Preview
import androidx.compose.ui.unit.dp
import com.example.layanalyzer.R
import com.example.layanalyzer.data.PacketRepository
import com.example.layanalyzer.data.RtpRepository
import com.example.layanalyzer.media.ExternalPlayerLauncher
import com.example.layanalyzer.media.VideoMuxFormat
import com.example.layanalyzer.model.MIME_VIDEO_H264
import com.example.layanalyzer.model.MIME_VIDEO_HEVC
import com.example.layanalyzer.model.RtpCodecCapabilities
import com.example.layanalyzer.model.RtpCodecCatalog
import com.example.layanalyzer.model.RtpCodecSource
import com.example.layanalyzer.model.RtpCodecUnavailableReason
import com.example.layanalyzer.model.RtpDecodability
import com.example.layanalyzer.model.RtpExportFormat
import com.example.layanalyzer.model.RtpProgress
import com.example.layanalyzer.model.RtpScanResult
import com.example.layanalyzer.model.RtpStream
import com.example.layanalyzer.model.RtpVideoDecoderAvailability
import com.example.layanalyzer.model.RtpVideoExportFormat
import com.example.layanalyzer.model.RtpVideoPreviewAvailability
import com.example.layanalyzer.model.rtpVideoFileName
import com.example.layanalyzer.ui.theme.LayerAnalyzerTheme
import com.example.layanalyzer.viewmodel.RtpExportDestination
import com.example.layanalyzer.viewmodel.RtpExportUiState
import com.example.layanalyzer.viewmodel.RtpScanUiState
import com.example.layanalyzer.viewmodel.RtpVideoExportPhase
import com.example.layanalyzer.viewmodel.RtpVideoExportUiState
import com.example.layanalyzer.viewmodel.RtpVideoOpenUiState
import java.io.File
import java.util.Locale
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext

/**
 * RTP 流列表页（RTP1-UI-01 + RTP1-UI-02）。
 *
 * 整页结构参照 `HttpObjectsScreen.kt`：`Scaffold` + `TopAppBar` + 返回 + 刷新；
 * 每流一行（`RtpStreamRow` 的布局思路参考 `CommunicationDialog.kt`，但不使用它的
 * `CommunicationAnalysis` 数据）。
 *
 * 颜色一律取 `MaterialTheme.colorScheme` 的语义色，保证深色模式可读，不硬编码 `Color(0xFF…)`。
 *
 * RTP1-UI-02 在每张卡片上加了操作菜单（「过滤出此流」/「指定编码」），并调用
 * [onFilterStream] / [onMapCodec] 把整条流交回宿主。RTP2-UI-03 为可解码流增加
 * 播放和导出入口，并支持长按多选后把整组流交给播放器或导出。
 *
 * 「指定编码」对话框由 [RtpCodecMapDialog] 提供（公开 composable），供宿主（RTP1-UI-03）
 * 调用；本屏幕不自己承载该对话框，以免改变 [onMapCodec] 的语义。
 */
@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun RtpStreamsScreen(
    state: RtpScanUiState,
    heuristicEnabled: Boolean,
    onScan: (limitToDisplayFilter: Boolean) -> Unit,
    onCancel: () -> Unit,
    onToggleHeuristic: (Boolean) -> Unit,
    onFilterStream: (RtpStream) -> Unit,
    onMapCodec: (RtpStream) -> Unit,     // M1 打开 KT-04 对话框
    onBack: () -> Unit,
    /** 打开该流的播放页面，等待用户手动播放。 */
    onOpenPlayer: (RtpStream) -> Unit,
    /**
     * 进入「VoIP 呼叫」列表（RTP3-UI-01 的入口接线）。为 `null` 时顶栏不显示该按钮，
     * 于是旧的调用点（含预览）不必改动就仍然编译。
     */
    onOpenVoipCalls: (() -> Unit)? = null,
    highlightedStreamId: String? = null,
    onPlayStream: (RtpStream) -> Unit = {},
    onPlayStreams: (List<RtpStream>) -> Unit = {},
    onExportWav: (List<RtpStream>, List<RtpExportDestination>) -> Unit = { _, _ -> },
    onExportRaw: (List<RtpStream>, List<RtpExportDestination>) -> Unit = { _, _ -> },
    /**
     * RTP4-KT-03 的导出格式对话框选完之后调用：宿主负责把 (流, 格式, 目的地) 交给
     * `RtpViewModel.exportFormat`。默认空实现，所以旧调用点（含预览）不必改动。
     */
    onExportFormat: (RtpStream, RtpExportFormat, RtpExportDestination) -> Unit =
        { _, _, _ -> },
    exportState: RtpExportUiState = RtpExportUiState.Idle,
    onClearExportState: () -> Unit = {},
    /**
     * RTP5-UI-01：视频导出（MP4 / 裸流）的状态与它的目的地写入。与音频的 [exportState]
     * 各自独立（`RtpViewModel.videoExportState`），所以两条线的进度与结果不会互相覆盖。
     */
    videoExportState: RtpVideoExportUiState = RtpVideoExportUiState.Idle,
    onExportVideo: (
        RtpStream,
        RtpVideoExportFormat,
        RtpExportDestination,
        /* startAtKeyframe = */ Boolean,
        /* dropCorrupt = */ Boolean
    ) -> Unit = { _, _, _, _, _ -> },
    onClearVideoExportState: () -> Unit = {},
    /**
     * RTP5-UI-01：「外部播放」的准备状态（`RtpViewModel.videoOpenState`）。拿到 `Ready` 后
     * 由本屏幕用 [ExternalPlayerLauncher] 交给外部应用 —— 与 `RtpPlayerScreen` 对
     * `externalOpenState` 的分工相同（谁有 `Context` 谁打开）。
     */
    videoOpenState: RtpVideoOpenUiState = RtpVideoOpenUiState.Idle,
    onOpenVideoExternal: (RtpStream) -> Unit = {},
    onClearVideoOpenState: () -> Unit = {},
    /**
     * RTP5-UI-01：本机有没有 H.265 解码器，只用于导出选项对话框里那句提示
     * （[RtpVideoDecoderAvailability.noticeRequired] 为 true 时才显示）。
     * [onRefreshHevcDecoderAvailability] 在打开对话框时问一次，免得拿一个过期的答案提示用户。
     */
    hevcDecoderAvailability: RtpVideoDecoderAvailability = RtpVideoDecoderAvailability.UNKNOWN,
    onRefreshHevcDecoderAvailability: () -> Unit = {},
    /**
     * RTP5-UI-01：哪些流有可预览的 MP4（宿主按导出结果记的账），以及 RTP5-KT-03 的可用性
     * 结论。「应用内预览」这个入口**两个都满足**时才出现：前者回答「这份 MP4 属于哪条流」
     * （`RtpVideoPreviewAvailability.Ready` 里没有流 id），后者回答「这两个文件 + 这台设备
     * 现在能不能播」。任一不满足就整条不显示 —— 卡片要的是不显示，不是一个按不动的灰按钮。
     */
    videoPreviewStreamIds: Set<String> = emptySet(),
    videoPreviewAvailability: RtpVideoPreviewAvailability =
        RtpVideoPreviewAvailability.NoExport,
    /**
     * 一次 MP4 导出成功后交回宿主：宿主记账（流 → 产物路径）并让
     * `RtpViewModel.refreshVideoPreviewAvailability` 问一次 KT-03 的判定。
     */
    onVideoPreviewAvailable: (RtpStream, /* mp4Path = */ String, /* indexPath = */ String) -> Unit =
        { _, _, _ -> },
    onOpenVideoPreview: (RtpStream) -> Unit = {},
    /**
     * RTP5-UI-01：视频流卡片被整块点击、而这条流还没有可播的 MP4 时走这里 ——
     * 宿主转 `RtpViewModel.prepareVideoPreview`，把该流的 ES 与 MP4 封装进缓存后
     * 打开预览页。**不弹 SAF、不写用户可见的文件**：想真的存下来仍然走 ⋮ 菜单的
     * 「导出 MP4」，那一步的落盘语义没变。
     */
    onPrepareVideoPreview: (RtpStream) -> Unit = {},
    /** 大文件的视频导出 / 外部打开要几分钟，进度条上的取消走这里。 */
    onCancelVideoExport: () -> Unit = {},
    /** 大文件的音频导出同样要能停。 */
    onCancelAudioExport: () -> Unit = {}
) {
    val context = LocalContext.current
    val snackbarHostState = remember { SnackbarHostState() }
    val scope = rememberCoroutineScope()
    var menuExpanded by remember { mutableStateOf(false) }
    var showHeuristicWarning by remember { mutableStateOf(false) }
    var decodableReason by remember { mutableStateOf<String?>(null) }
    var selectionMode by remember { mutableStateOf(false) }
    var selectedStreamIds by remember { mutableStateOf<Set<String>>(emptySet()) }
    var pendingWavExport by remember { mutableStateOf<List<RtpStream>?>(null) }
    var pendingRawExport by remember { mutableStateOf<List<RtpStream>?>(null) }
    var wavDestinations by remember { mutableStateOf<List<RtpExportDestination>>(emptyList()) }
    var rawDestinations by remember { mutableStateOf<List<RtpExportDestination>>(emptyList()) }
    // RTP4-KT-03：导出格式对话框的当前流，以及正在等 SAF 目的地的那一次选择。
    var formatDialogStream by remember { mutableStateOf<RtpStream?>(null) }
    var pendingFormatStream by remember { mutableStateOf<RtpStream?>(null) }
    // RTP5-UI-01：视频那条线的本地状态。`videoDialogRequest` 是导出选项对话框正在讲哪条流、
    // 哪一种产物；`pendingVideoExport` 是「选完产物、等用户挑 SAF 目的地」的那一次选择；
    // `videoExportStream` 是**已经开始导出**的那条流 —— 结果摘要与「应用内预览」都要知道
    // 数字属于谁，而它在用户关掉摘要之前一直在用。
    var videoDialogRequest by remember { mutableStateOf<RtpVideoDialogRequest?>(null) }
    var pendingVideoExport by remember { mutableStateOf<PendingVideoExport?>(null) }
    var videoExportStream by remember { mutableStateOf<RtpStream?>(null) }

    val clearSelection = {
        selectionMode = false
        selectedStreamIds = emptySet()
    }
    val toggleSelection: (RtpStream) -> Unit = { stream ->
        val next = if (stream.id in selectedStreamIds) {
            selectedStreamIds - stream.id
        } else {
            selectedStreamIds + stream.id
        }
        selectedStreamIds = next
        if (next.isEmpty()) selectionMode = false
    }
    val enterSelection: (RtpStream) -> Unit = { stream ->
        selectionMode = true
        selectedStreamIds = setOf(stream.id)
    }
    val startWavExport: (List<RtpStream>) -> Unit = { streams ->
        if (streams.isNotEmpty()) {
            pendingWavExport = streams
            wavDestinations = emptyList()
        }
    }
    val startRawExport: (List<RtpStream>) -> Unit = { streams ->
        val exportable = streams.filter { stream ->
            stream.decodable == RtpDecodability.YES && rtpRawExportFileName(stream) != null
        }
        if (exportable.isNotEmpty()) {
            pendingRawExport = exportable
            rawDestinations = emptyList()
        }
    }

    val wavExportLauncher = rememberRtpWavExportLauncher { uri ->
        val streams = pendingWavExport
        if (streams != null) {
            if (uri == null) {
                pendingWavExport = null
                wavDestinations = emptyList()
            } else {
                val stream = streams.getOrNull(wavDestinations.size)
                if (stream == null) {
                    pendingWavExport = null
                    wavDestinations = emptyList()
                } else {
                    wavDestinations = wavDestinations + rtpExportDestination(
                        context = context,
                        uri = uri,
                        displayName = rtpWavExportFileName(stream)
                    )
                }
            }
        }
    }
    val rawExportLauncher = rememberRtpRawExportLauncher { uri ->
        val streams = pendingRawExport
        if (streams != null) {
            if (uri == null) {
                pendingRawExport = null
                rawDestinations = emptyList()
            } else {
                val stream = streams.getOrNull(rawDestinations.size)
                val displayName = stream?.let(::rtpRawExportFileName)
                if (stream == null || displayName == null) {
                    pendingRawExport = null
                    rawDestinations = emptyList()
                } else {
                    rawDestinations = rawDestinations + rtpExportDestination(
                        context = context,
                        uri = uri,
                        displayName = displayName
                    )
                }
            }
        }
    }

    // RTP4-KT-03：导出格式对话框选定格式后，SAF 目的地的回调。五种格式各有一个
    // launcher（CreateDocument 的 MIME 在构造时固定），全部无条件创建。
    fun onFormatUri(format: RtpExportFormat, uri: Uri?) {
        val stream = pendingFormatStream
        pendingFormatStream = null
        if (stream == null || uri == null) return
        val displayName = rtpFormatExportFileName(stream, format)
        if (displayName == null) {
            scope.launch {
                snackbarHostState.showSnackbar(
                    context.getString(R.string.rtp_raw_export_unavailable)
                )
            }
            return
        }
        onExportFormat(
            stream,
            format,
            rtpExportDestination(context = context, uri = uri, displayName = displayName)
        )
    }
    val wavFormatLauncher = rememberRtpFormatExportLauncher(RtpExportFormat.WAV) {
        onFormatUri(RtpExportFormat.WAV, it)
    }
    val rawFormatLauncher = rememberRtpFormatExportLauncher(RtpExportFormat.RAW) {
        onFormatUri(RtpExportFormat.RAW, it)
    }
    val amrFormatLauncher = rememberRtpFormatExportLauncher(RtpExportFormat.AMR) {
        onFormatUri(RtpExportFormat.AMR, it)
    }
    val awbFormatLauncher = rememberRtpFormatExportLauncher(RtpExportFormat.AWB) {
        onFormatUri(RtpExportFormat.AWB, it)
    }
    val opusFormatLauncher = rememberRtpFormatExportLauncher(RtpExportFormat.OPUS) {
        onFormatUri(RtpExportFormat.OPUS, it)
    }
    val formatLaunchers = mapOf(
        RtpExportFormat.WAV to wavFormatLauncher,
        RtpExportFormat.RAW to rawFormatLauncher,
        RtpExportFormat.AMR to amrFormatLauncher,
        RtpExportFormat.AWB to awbFormatLauncher,
        RtpExportFormat.OPUS to opusFormatLauncher
    )

    // --------------------------------------------------------------- RTP5-UI-01：视频那一组
    //
    // 视频的产物 MIME 由「格式 + 编码」两个变量决定（`.mp4` / `.h264` / `.h265`），而
    // CreateDocument 的 MIME 在构造时就固定，所以三种各建一个 launcher、按 MIME 取用 ——
    // 与上面音频那五个格式的 launcher 是同一种做法，也同样是**无条件**创建（不能按当前流
    // 算一个 MIME 传进来：`rememberLauncherForActivityResult` 只在第一次组合时取 contract，
    // 那样第一条流的 MIME 会一直用到会话结束）。
    fun onVideoUri(uri: Uri?) {
        val pending = pendingVideoExport
        pendingVideoExport = null
        if (pending == null || uri == null) return
        val displayName = rtpVideoFileName(pending.stream, pending.format) ?: return
        videoExportStream = pending.stream
        onExportVideo(
            pending.stream,
            pending.format,
            rtpExportDestination(context = context, uri = uri, displayName = displayName),
            pending.startAtKeyframe,
            pending.dropCorrupt
        )
    }
    val mp4VideoLauncher = rememberRtpVideoExportLauncher(VideoMuxFormat.MIME_MP4) {
        onVideoUri(it)
    }
    val h264VideoLauncher = rememberRtpVideoExportLauncher(MIME_VIDEO_H264) { onVideoUri(it) }
    val hevcVideoLauncher = rememberRtpVideoExportLauncher(MIME_VIDEO_HEVC) { onVideoUri(it) }
    val videoLaunchers = mapOf(
        VideoMuxFormat.MIME_MP4 to mp4VideoLauncher,
        MIME_VIDEO_H264 to h264VideoLauncher,
        MIME_VIDEO_HEVC to hevcVideoLauncher
    )
    val startVideoExport: (RtpStream, RtpVideoExportFormat, Boolean, Boolean) -> Unit =
        { stream, format, startAtKeyframe, dropCorrupt ->
            val displayName = rtpVideoFileName(stream, format)
            val launcher = rtpVideoExportMimeType(stream.codec, format)?.let(videoLaunchers::get)
            if (displayName == null || launcher == null) {
                // 菜单里这种流（`PS`）的视频动作全是置灰的，所以这里是同一条判定的兜底：
                // 拿不出文件名或 MIME 就说明白，不猜一个后缀去写文件（README §4.5.4）。
                scope.launch {
                    snackbarHostState.showSnackbar(
                        context.getString(R.string.rtp_video_export_none)
                    )
                }
            } else {
                pendingVideoExport =
                    PendingVideoExport(stream, format, startAtKeyframe, dropCorrupt)
                launcher.launch(displayName)
            }
        }

    // 视频导出的失败：与音频的 exportState 同一种处理（提示 + 清状态）。成功**不在这里**
    // 处理：结果摘要是对话框，要一直留到用户关掉，见下面的 videoExportState 分支。
    LaunchedEffect(videoExportState) {
        when (val current = videoExportState) {
            RtpVideoExportUiState.Idle,
            is RtpVideoExportUiState.Running -> Unit

            is RtpVideoExportUiState.Finished -> {
                // 成功那条路只做一件事：如果是 MP4，把「这条流有一份可预览的产物」交回
                // 宿主。裸流没有可预览的东西（KT-01 的封装器只吃 ES + `.vidx`），所以不问。
                if (current.summary.format != RtpVideoExportFormat.MP4) return@LaunchedEffect
                val stream = videoExportStream ?: return@LaunchedEffect
                val mp4Path = current.summary.files.firstOrNull()?.filePath
                    ?: return@LaunchedEffect
                val indexPath = current.summary.results[stream.id]?.indexPath.orEmpty()
                if (mp4Path.isNotBlank() && indexPath.isNotBlank()) {
                    onVideoPreviewAvailable(stream, mp4Path, indexPath)
                }
            }

            is RtpVideoExportUiState.Error -> {
                snackbarHostState.showSnackbar(
                    current.message.ifBlank {
                        context.getString(R.string.rtp_video_export_failed)
                    }
                )
                videoExportStream = null
                onClearVideoExportState()
            }
        }
    }

    // 「外部播放」：导出的活由 ViewModel 做（`prepareExternalVideoOpen`），本屏幕只负责把
    // 产物交给外部应用 —— 与 RtpPlayerScreen 对 `externalOpenState` 的分工完全相同。
    LaunchedEffect(videoOpenState) {
        when (val current = videoOpenState) {
            RtpVideoOpenUiState.Idle,
            is RtpVideoOpenUiState.Preparing -> Unit

            is RtpVideoOpenUiState.Error -> {
                snackbarHostState.showSnackbar(
                    current.message.ifBlank {
                        context.getString(R.string.rtp_video_export_failed)
                    }
                )
                onClearVideoOpenState()
            }

            is RtpVideoOpenUiState.Ready -> {
                val candidates = current.mimeTypes.map { mimeType ->
                    ExternalPlayerLauncher.ExternalOpenCandidate(
                        file = File(current.filePath),
                        mimeType = mimeType
                    )
                }
                val opened = runCatching {
                    ExternalPlayerLauncher.openFirstAvailable(
                        context = context,
                        candidates = candidates,
                        chooserTitleRes = R.string.rtp_open_external_video_chooser_title
                    )
                }.getOrNull()
                // 只有「用的是最后那条通用 MIME」才提示：`video/h264` 没有应用认领是常态，
                // 退到 `application/octet-stream` 打开的是同一个文件（KT-02 卡片第 1 条）。
                val message = when {
                    opened == null -> context.getString(R.string.rtp_no_player_app_format)
                    opened.mimeType == RtpExportFormat.RAW.mimeType ->
                        context.getString(R.string.rtp_open_external_video_fallback)
                    else -> null
                }
                if (message != null) snackbarHostState.showSnackbar(message)
                onClearVideoOpenState()
            }
        }
    }

    LaunchedEffect(pendingWavExport, wavDestinations.size) {
        val streams = pendingWavExport ?: return@LaunchedEffect
        if (wavDestinations.size == streams.size) {
            val destinations = wavDestinations
            pendingWavExport = null
            wavDestinations = emptyList()
            onExportWav(streams, destinations)
        } else {
            wavExportLauncher.launch(rtpWavExportFileName(streams[wavDestinations.size]))
        }
    }

    LaunchedEffect(pendingRawExport, rawDestinations.size) {
        val streams = pendingRawExport ?: return@LaunchedEffect
        if (rawDestinations.size == streams.size) {
            val destinations = rawDestinations
            pendingRawExport = null
            rawDestinations = emptyList()
            onExportRaw(streams, destinations)
        } else {
            val fileName = rtpRawExportFileName(streams[rawDestinations.size])
            if (fileName == null) {
                pendingRawExport = null
                rawDestinations = emptyList()
            } else {
                rawExportLauncher.launch(fileName)
            }
        }
    }

    LaunchedEffect(exportState) {
        when (val current = exportState) {
            RtpExportUiState.Idle,
            is RtpExportUiState.Running -> Unit

            is RtpExportUiState.Error -> {
                snackbarHostState.showSnackbar(
                    current.message.ifBlank {
                        context.getString(R.string.rtp_player_export_failed)
                    }
                )
                onClearExportState()
            }

            is RtpExportUiState.Finished -> {
                val summary = current.summary
                val message = when {
                    summary.failures.isEmpty() ->
                        context.getString(R.string.rtp_export_complete)

                    summary.files.isEmpty() ->
                        summary.failures.first().message.ifBlank {
                            context.getString(R.string.rtp_player_export_failed)
                        }

                    else -> context.getString(
                        R.string.rtp_export_partial,
                        summary.files.size,
                        summary.files.size + summary.failures.size,
                        summary.failures.size
                    )
                }
                snackbarHostState.showSnackbar(message)
                onClearExportState()
            }
        }
    }

    LaunchedEffect(state) {
        if (state !is RtpScanUiState.Done) clearSelection()
    }
    BackHandler {
        if (selectionMode) clearSelection() else onBack()
    }

    // 打开启发式识别前先弹确认框；关闭时直接生效。
    val toggleHeuristic: (Boolean) -> Unit = { next ->
        if (next) showHeuristicWarning = true else onToggleHeuristic(false)
    }

    Scaffold(
        topBar = {
            TopAppBar(
                title = {
                    Text(
                        stringResource(R.string.rtp_streams_title),
                        maxLines = 1,
                        overflow = TextOverflow.Ellipsis
                    )
                },
                navigationIcon = {
                    IconButton(onClick = { if (selectionMode) clearSelection() else onBack() }) {
                        Icon(Icons.AutoMirrored.Filled.ArrowBack, stringResource(R.string.back))
                    }
                },
                actions = {
                    onOpenVoipCalls?.let { openVoipCalls ->
                        IconButton(onClick = openVoipCalls) {
                            Icon(
                                Icons.Default.Call,
                                stringResource(R.string.voip_calls_title)
                            )
                        }
                    }
                    IconButton(onClick = { onScan(false) }) {
                        Icon(Icons.Default.Refresh, stringResource(R.string.refresh))
                    }
                    IconButton(onClick = { menuExpanded = true }) {
                        Icon(Icons.Default.MoreVert, stringResource(R.string.rtp_more_actions))
                    }
                    DropdownMenu(expanded = menuExpanded, onDismissRequest = { menuExpanded = false }) {
                        DropdownMenuItem(
                            text = {
                                Text(
                                    stringResource(
                                        if (heuristicEnabled) R.string.rtp_heuristic_disable
                                        else R.string.rtp_heuristic_enable
                                    ),
                                    maxLines = 1,
                                    overflow = TextOverflow.Ellipsis
                                )
                            },
                            onClick = {
                                menuExpanded = false
                                toggleHeuristic(!heuristicEnabled)
                            },
                            trailingIcon = {
                                Switch(
                                    checked = heuristicEnabled,
                                    onCheckedChange = { next ->
                                        menuExpanded = false
                                        toggleHeuristic(next)
                                    }
                                )
                            }
                        )
                    }
                }
            )
        },
        snackbarHost = { SnackbarHost(snackbarHostState) }
    ) { padding ->
        Column(
            modifier = Modifier
                .padding(padding)
                .fillMaxSize()
                .padding(horizontal = 12.dp)
        ) {
            when (state) {
                RtpScanUiState.Idle -> {
                    Button(
                        onClick = { onScan(false) },
                        modifier = Modifier.padding(top = 16.dp)
                    ) {
                        Text(stringResource(R.string.rtp_scan_start))
                    }
                }

                is RtpScanUiState.Running -> {
                    Text(
                        stringResource(R.string.rtp_scan_progress, state.done, state.total),
                        modifier = Modifier.padding(top = 16.dp),
                        style = MaterialTheme.typography.bodyMedium,
                        maxLines = 1,
                        overflow = TextOverflow.Ellipsis
                    )
                    if (state.total > 0) {
                        LinearProgressIndicator(
                            progress = { (state.done.toFloat() / state.total).coerceIn(0f, 1f) },
                            modifier = Modifier.fillMaxWidth().padding(top = 8.dp)
                        )
                    } else {
                        // total <= 0 时无法计算比例，退化为不确定进度条。
                        LinearProgressIndicator(modifier = Modifier.fillMaxWidth().padding(top = 8.dp))
                    }
                    Button(
                        onClick = onCancel,
                        modifier = Modifier.padding(top = 12.dp)
                    ) {
                        Text(stringResource(R.string.cancel))
                    }
                }

                is RtpScanUiState.Error -> {
                    Text(
                        state.message,
                        modifier = Modifier.padding(top = 16.dp),
                        color = MaterialTheme.colorScheme.error
                    )
                    Button(
                        onClick = { onScan(false) },
                        modifier = Modifier.padding(top = 12.dp)
                    ) {
                        Text(stringResource(R.string.retry))
                    }
                }

                RtpScanUiState.Cancelled -> {
                    Text(
                        stringResource(R.string.rtp_scan_cancelled),
                        modifier = Modifier.padding(top = 16.dp)
                    )
                    Button(
                        onClick = { onScan(false) },
                        modifier = Modifier.padding(top = 12.dp)
                    ) {
                        Text(stringResource(R.string.retry))
                    }
                }

                is RtpScanUiState.Done -> {
                    val videoRunning = videoExportState as? RtpVideoExportUiState.Running
                    val videoPreparing = videoOpenState as? RtpVideoOpenUiState.Preparing
                    val audioRunning = exportState as? RtpExportUiState.Running
                    if (videoRunning != null) {
                        ExportProgressBanner(
                            title = stringResource(
                                if (videoRunning.phase == RtpVideoExportPhase.MUXING) {
                                    R.string.rtp_video_export_muxing
                                } else {
                                    R.string.rtp_video_export_running
                                }
                            ),
                            progress = videoRunning.progress,
                            onCancel = onCancelVideoExport
                        )
                    }
                    if (videoPreparing != null) {
                        ExportProgressBanner(
                            title = stringResource(R.string.rtp_video_export_running),
                            progress = videoPreparing.progress,
                            onCancel = onCancelVideoExport
                        )
                    }
                    if (audioRunning != null) {
                        ExportProgressBanner(
                            title = stringResource(R.string.rtp_audio_export_running),
                            progress = audioRunning.progress,
                            onCancel = onCancelAudioExport
                        )
                    }
                    DoneContent(
                        result = state.result,
                        onOpenPlayer = onOpenPlayer,
                        onShowDecodableReason = { decodableReason = it },
                        onPrepareAndPreview = onPrepareVideoPreview,
                        onEnableHeuristic = { showHeuristicWarning = true },
                        onFilterStream = onFilterStream,
                        onMapCodec = onMapCodec,
                        highlightedStreamId = highlightedStreamId,
                        onPlayStream = onPlayStream,
                        selectionMode = selectionMode,
                        selectedStreamIds = selectedStreamIds,
                        exportRunning = exportState is RtpExportUiState.Running,
                        onEnterSelection = enterSelection,
                        onToggleSelection = toggleSelection,
                        onExitSelection = clearSelection,
                        onPlayStreams = onPlayStreams,
                        onExportWav = startWavExport,
                        onExportRaw = startRawExport,
                        onExportFormat = { stream -> formatDialogStream = stream },
                        videoMenu = RtpVideoMenu(
                            previewReady = videoPreviewAvailability is
                                RtpVideoPreviewAvailability.Ready,
                            previewStreamIds = videoPreviewStreamIds,
                            running = videoExportState is RtpVideoExportUiState.Running,
                            onOpenExternal = onOpenVideoExternal,
                            onExport = { stream, format ->
                                // H.265 的「本机没有解码器」提示要现问一次：那一次探测是
                                // 一次 `MediaCodecList` 查询，拿上一次导出的旧答案提示用户
                                // 有可能是在说另一台设备/另一个时刻的情况。
                                if (VideoMuxFormat.mimeFor(stream.codec) == VideoMuxFormat.MIME_H265) {
                                    onRefreshHevcDecoderAvailability()
                                }
                                videoDialogRequest = RtpVideoDialogRequest(stream, format)
                            },
                            onPreview = onOpenVideoPreview
                        )
                    )
                }
            }
        }
    }

    if (showHeuristicWarning) {
        AlertDialog(
            onDismissRequest = { showHeuristicWarning = false },
            title = { Text(stringResource(R.string.rtp_heuristic_warning_title)) },
            text = { Text(stringResource(R.string.rtp_heuristic_warning_message)) },
            confirmButton = {
                TextButton(onClick = {
                    showHeuristicWarning = false
                    onToggleHeuristic(true)
                }) {
                    Text(stringResource(R.string.rtp_heuristic_enable_confirm))
                }
            },
            dismissButton = {
                TextButton(onClick = { showHeuristicWarning = false }) {
                    Text(stringResource(R.string.cancel))
                }
            }
        )
    }

    val unknownText = stringResource(R.string.unknown)
    decodableReason?.let { reason ->
        AlertDialog(
            onDismissRequest = { decodableReason = null },
            title = { Text(stringResource(R.string.rtp_decodable_reason_title)) },
            text = {
                Text(reason.ifBlank { unknownText })
            },
            confirmButton = {
                TextButton(onClick = { decodableReason = null }) {
                    Text(stringResource(R.string.close))
                }
            }
        )
    }

    // RTP4-KT-03：导出格式菜单。列出的格式由 RtpCodecCatalog 的表与这条流的实际
    // 状态共同决定（rtpExportableFormats），选中后走对应 MIME 的 SAF 目的地。
    formatDialogStream?.let { stream ->
        RtpExportFormatDialog(
            stream = stream,
            onSelect = { format ->
                formatDialogStream = null
                val displayName = rtpFormatExportFileName(stream, format)
                if (displayName != null) {
                    pendingFormatStream = stream
                    formatLaunchers.getValue(format).launch(displayName)
                }
            },
            onDismiss = { formatDialogStream = null }
        )
    }

    // RTP5-UI-01：视频导出的两个对话框。选项对话框讲的是菜单里选定的那一次导出；结果摘要
    // 一直留到用户关掉为止（关掉才清状态，`Idle` 也才让对话框消失）。
    videoDialogRequest?.let { request ->
        RtpVideoExportDialog(
            stream = request.stream,
            format = request.format,
            // 只有 H.265 才问 HEVC 解码器（探针回答的就是它），而且只在确认「没有」时提示：
            // `noticeRequired` 对 AVAILABLE 与 UNKNOWN 都是 false（KT-02 的 fail-open）。
            hevcDecoderMissing = VideoMuxFormat.mimeFor(request.stream.codec) ==
                VideoMuxFormat.MIME_H265 &&
                hevcDecoderAvailability.noticeRequired,
            onConfirm = { startAtKeyframe, dropCorrupt ->
                videoDialogRequest = null
                startVideoExport(request.stream, request.format, startAtKeyframe, dropCorrupt)
            },
            onDismiss = { videoDialogRequest = null }
        )
    }

    // RTP5-UI-01：结果摘要只在「这次导出确实是本屏幕发起的那一条流」时显示。摘要里那些
    // 数字属于某一条流，说不清是哪条就不显示（离开本页时下面的 DisposableEffect 还会把
    // 状态清掉，回来时不会又冒出一个没有归属的摘要）。
    val finishedExport = videoExportState as? RtpVideoExportUiState.Finished
    val exportedStream = videoExportStream
    if (finishedExport != null && exportedStream != null) {
        // 「预览入口为什么没有」：只有**编码**这一档值得在这里说（设备没有该编码的解码器），
        // 而且只有这次导出的是 MP4 时才说 —— 裸流本来就没有可预览的东西，说了反而误导。
        val noDecoder = (videoPreviewAvailability as? RtpVideoPreviewAvailability.UnsupportedCodec)
            ?.takeIf { finishedExport.summary.format == RtpVideoExportFormat.MP4 }
        // 关掉摘要（无论是按「关闭」还是按了「应用内预览」）都要收干净：状态一清，摘要就
        // 不会在从预览页回来时又出现一次。
        val finishVideoResult: () -> Unit = {
            videoExportStream = null
            onClearVideoExportState()
        }
        RtpVideoExportResultDialog(
            summary = finishedExport.summary,
            result = finishedExport.summary.results[exportedStream.id],
            canPreview = finishedExport.summary.format == RtpVideoExportFormat.MP4 &&
                exportedStream.id in videoPreviewStreamIds &&
                videoPreviewAvailability is RtpVideoPreviewAvailability.Ready,
            previewNotice = noDecoder?.let {
                context.getString(R.string.rtp_video_preview_no_decoder, it.codec)
            },
            onPreview = {
                onOpenVideoPreview(exportedStream)
                finishVideoResult()
            },
            onDismiss = finishVideoResult
        )
    }

    // 离开这一页（返回、过滤、跳数据包都算）就没有导出的上下文了：清掉状态，免得下次进来
    // 先看见一份属于上一次的摘要。预览页会用同一个状态，但那时它已经显示过了。
    DisposableEffect(Unit) {
        onDispose { onClearVideoExportState() }
    }
}

/**
 * RTP5-UI-01：导出选项对话框正在讲哪条流、哪一种产物。
 *
 * 产物是**菜单项选定的**（卡片上「导出 MP4」与「导出裸流」是两个条目），对话框只负责把
 * 两个选项收齐再确认 —— 所以它不需要「选格式」这一步，也就不会出现「选了格式才发现这条流
 * 导不出来」的空转。
 */
private data class RtpVideoDialogRequest(
    val stream: RtpStream,
    val format: RtpVideoExportFormat
)

/** RTP5-UI-01：已经选定产物、正在等用户挑 SAF 目的地的那一次导出。 */
private data class PendingVideoExport(
    val stream: RtpStream,
    val format: RtpVideoExportFormat,
    val startAtKeyframe: Boolean,
    val dropCorrupt: Boolean
)

/**
 * RTP5-UI-01：视频流卡片菜单需要的那一份状态与三个动作。
 *
 * 打包成一个类型只是为了不让 [DoneContent] 与 [RtpStreamCard] 的参数表再长六个 —— 与
 * `RtpScanUiState` 那种「把一件事的几个字段放一起」同一种做法。
 *
 * [previewReady] 来自 `RtpViewModel.videoPreviewAvailability`（KT-03 的判定：文件在、这台
 * 设备也能解码），[previewStreamIds] 来自宿主记的账（哪条流有那份 MP4）。两者**取交集**
 * 才让「应用内预览」出现：前者说的是「这两个文件现在能不能播」，但它里面没有流 id。
 */
private data class RtpVideoMenu(
    val previewReady: Boolean,
    val previewStreamIds: Set<String>,
    /** 一次视频导出正在进行：那三个动作先按住，免得同一条流被按下两次。 */
    val running: Boolean = false,
    val onOpenExternal: (RtpStream) -> Unit,
    val onExport: (RtpStream, RtpVideoExportFormat) -> Unit,
    val onPreview: (RtpStream) -> Unit
)

/**
 * 导出进行中的提示。大文件在这里要等很久，没有这条就会看起来像卡住了。
 *
 * [progress] 为 null 或 `total <= 0` 时用不确定进度条：还没收到第一个计数，但工作已经开始。
 * `total == 100` 是百分数；别的总数按「已完成 / 总数」显示。
 */
@Composable
private fun ExportProgressBanner(
    title: String,
    progress: RtpProgress?,
    onCancel: () -> Unit
) {
    Text(
        title,
        modifier = Modifier.padding(top = 12.dp),
        style = MaterialTheme.typography.bodyMedium,
        maxLines = 1,
        overflow = TextOverflow.Ellipsis
    )
    if (progress != null && progress.total > 0) {
        Text(
            if (progress.total == 100) {
                stringResource(R.string.rtp_export_progress_percent, progress.done)
            } else {
                stringResource(R.string.rtp_scan_progress, progress.done, progress.total)
            },
            modifier = Modifier.padding(top = 4.dp),
            style = MaterialTheme.typography.bodySmall,
            color = MaterialTheme.colorScheme.onSurfaceVariant,
            maxLines = 1,
            overflow = TextOverflow.Ellipsis
        )
        LinearProgressIndicator(
            progress = {
                (progress.done.toFloat() / progress.total.toFloat()).coerceIn(0f, 1f)
            },
            modifier = Modifier.fillMaxWidth().padding(top = 8.dp)
        )
    } else {
        LinearProgressIndicator(modifier = Modifier.fillMaxWidth().padding(top = 8.dp))
    }
    Button(
        onClick = onCancel,
        modifier = Modifier.padding(top = 8.dp)
    ) {
        Text(stringResource(R.string.cancel))
    }
}

@Composable
private fun ColumnScope.DoneContent(
    result: RtpScanResult,
    onOpenPlayer: (RtpStream) -> Unit,
    onShowDecodableReason: (String) -> Unit,
    onPrepareAndPreview: (RtpStream) -> Unit,
    onEnableHeuristic: () -> Unit,
    onFilterStream: (RtpStream) -> Unit,
    onMapCodec: (RtpStream) -> Unit,
    highlightedStreamId: String?,
    onPlayStream: (RtpStream) -> Unit,
    selectionMode: Boolean,
    selectedStreamIds: Set<String>,
    exportRunning: Boolean,
    onEnterSelection: (RtpStream) -> Unit,
    onToggleSelection: (RtpStream) -> Unit,
    onExitSelection: () -> Unit,
    onPlayStreams: (List<RtpStream>) -> Unit,
    onExportWav: (List<RtpStream>) -> Unit,
    onExportRaw: (List<RtpStream>) -> Unit,
    onExportFormat: (RtpStream) -> Unit,
    videoMenu: RtpVideoMenu
) {
    Text(
        stringResource(R.string.rtp_streams_found, result.streams.size),
        modifier = Modifier.padding(top = 12.dp),
        style = MaterialTheme.typography.titleMedium,
        maxLines = 1,
        overflow = TextOverflow.Ellipsis
    )
    if (result.streamsTruncated) {
        // fail-closed：列表被截断时必须显式告知，绝不静默截断。
        Text(
            stringResource(R.string.rtp_streams_truncated_notice),
            modifier = Modifier.padding(top = 4.dp),
            style = MaterialTheme.typography.bodySmall,
            color = MaterialTheme.colorScheme.tertiary
        )
    }
    if (result.streams.isEmpty()) {
        Text(
            stringResource(R.string.rtp_no_streams),
            modifier = Modifier.padding(top = 16.dp)
        )
        Button(
            onClick = onEnableHeuristic,
            modifier = Modifier.padding(top = 12.dp)
        ) {
            Text(stringResource(R.string.rtp_heuristic_enable_action))
        }
    } else {
        val listState = rememberLazyListState()
        val selectedStreams = result.streams.filter { it.id in selectedStreamIds }
        if (selectionMode) {
            RtpSelectionToolbar(
                selectedStreams = selectedStreams,
                exportRunning = exportRunning,
                onPlaySelected = onPlayStreams,
                onExportWav = onExportWav,
                onExportRaw = onExportRaw,
                onExitSelection = onExitSelection
            )
        }
        LaunchedEffect(highlightedStreamId, result.streams) {
            val index = result.streams.indexOfFirst { it.id == highlightedStreamId }
            if (index >= 0) listState.animateScrollToItem(index)
        }
        LazyColumn(
            state = listState,
            modifier = Modifier
                .fillMaxWidth()
                .weight(1f)
                .padding(top = 8.dp)
        ) {
            items(result.streams, key = { it.id }) { stream ->
                RtpStreamCard(
                    stream = stream,
                    onOpenPlayer = onOpenPlayer,
                    onShowDecodableReason = onShowDecodableReason,
                    onPrepareAndPreview = onPrepareAndPreview,
                    onFilterStream = onFilterStream,
                    onMapCodec = onMapCodec,
                    highlighted = stream.id == highlightedStreamId,
                    onPlayStream = onPlayStream,
                    selectionMode = selectionMode,
                    selected = stream.id in selectedStreamIds,
                    onEnterSelection = onEnterSelection,
                    onToggleSelection = onToggleSelection,
                    onExportWav = { onExportWav(listOf(stream)) },
                    onExportRaw = { onExportRaw(listOf(stream)) },
                    onExportFormat = { onExportFormat(stream) },
                    videoMenu = videoMenu
                )
                HorizontalDivider()
            }
        }
    }
}

@Composable
private fun RtpSelectionToolbar(
    selectedStreams: List<RtpStream>,
    exportRunning: Boolean,
    onPlaySelected: (List<RtpStream>) -> Unit,
    onExportWav: (List<RtpStream>) -> Unit,
    onExportRaw: (List<RtpStream>) -> Unit,
    onExitSelection: () -> Unit
) {
    // RTP5-UI-01：这三个动作只对**音频**流成立。视频流在原生层同样是「可解码」，但它们解
    // 不出声音来，混进播放器或 WAV 导出的名单里只会得到一批 unsupported，所以名单在这里
    // 先减一次 —— 而上面的「N selected」照旧按用户真正选中的数量显示（选了两条流，一条是
    // 视频，就该说 2，不该偷偷说 1）。
    val audioStreams = selectedStreams.filterNot { rtpStreamIsVideo(it.codec) }
    Surface(
        modifier = Modifier
            .fillMaxWidth()
            .padding(top = 8.dp),
        shape = RoundedCornerShape(8.dp),
        color = MaterialTheme.colorScheme.surfaceVariant,
        tonalElevation = 2.dp
    ) {
        Row(
            modifier = Modifier
                .fillMaxWidth()
                .horizontalScroll(rememberScrollState())
                .padding(horizontal = 8.dp, vertical = 6.dp),
            horizontalArrangement = Arrangement.spacedBy(8.dp),
            verticalAlignment = Alignment.CenterVertically
        ) {
            Text(
                stringResource(R.string.rtp_selection_count, selectedStreams.size),
                style = MaterialTheme.typography.labelLarge,
                maxLines = 1
            )
            Button(
                onClick = { onPlaySelected(audioStreams) },
                enabled = audioStreams.isNotEmpty()
            ) {
                Icon(Icons.Default.PlayArrow, contentDescription = null)
                Text(stringResource(R.string.rtp_selection_play))
            }
            OutlinedButton(
                onClick = { onExportWav(audioStreams.filterDecodable()) },
                enabled = audioStreams.any { it.decodable == RtpDecodability.YES } &&
                    !exportRunning
            ) {
                Icon(Icons.Default.Download, contentDescription = null)
                Text(stringResource(R.string.rtp_selection_export_wav))
            }
            OutlinedButton(
                onClick = { onExportRaw(audioStreams.filterRawExportable()) },
                enabled = audioStreams.any(::isRawExportable) && !exportRunning
            ) {
                Icon(Icons.Default.Download, contentDescription = null)
                Text(stringResource(R.string.rtp_selection_export_raw))
            }
            IconButton(onClick = onExitSelection) {
                Icon(
                    Icons.Default.Close,
                    contentDescription = stringResource(R.string.rtp_selection_exit)
                )
            }
        }
    }
}

private fun List<RtpStream>.filterDecodable(): List<RtpStream> =
    filter { it.decodable == RtpDecodability.YES }

private fun List<RtpStream>.filterRawExportable(): List<RtpStream> =
    filter(::isRawExportable)

private fun isRawExportable(stream: RtpStream): Boolean =
    stream.decodable == RtpDecodability.YES && rtpRawExportFileName(stream) != null

@OptIn(ExperimentalFoundationApi::class)
@Composable
private fun RtpStreamCard(
    stream: RtpStream,
    onOpenPlayer: (RtpStream) -> Unit,
    onShowDecodableReason: (String) -> Unit,
    onFilterStream: (RtpStream) -> Unit,
    onMapCodec: (RtpStream) -> Unit,
    highlighted: Boolean = false,
    onPlayStream: (RtpStream) -> Unit,
    selectionMode: Boolean,
    selected: Boolean,
    onEnterSelection: (RtpStream) -> Unit,
    onToggleSelection: (RtpStream) -> Unit,
    onExportWav: (RtpStream) -> Unit,
    onExportRaw: (RtpStream) -> Unit,
    onExportFormat: (RtpStream) -> Unit,
    onPrepareAndPreview: (RtpStream) -> Unit,
    videoMenu: RtpVideoMenu
) {
    var menuExpanded by remember { mutableStateOf(false) }
    val rawExportUnavailable = stringResource(R.string.rtp_raw_export_unavailable)
    val videoExportUnavailable = stringResource(R.string.rtp_video_export_none)
    val showDecodableReason = {
        menuExpanded = false
        onShowDecodableReason(stream.decodableReason)
    }
    val showRawExportReason = {
        menuExpanded = false
        onShowDecodableReason(
            if (stream.decodable == RtpDecodability.YES) {
                rawExportUnavailable
            } else {
                stream.decodableReason
            }
        )
    }
    // RTP5-UI-01 的整卡点击归属。判据在 `rtpStreamCardTap`（纯逻辑，有 JVM 单测），
    // 这里只负责执行它 —— 视频流**不能**再走 `onOpenPlayer`：那扇门后面是音频解码器，
    // H.264 在 `RtpCodecCatalog.route()` 里是 UNSUPPORTED，点进去只会得到播放器页的
    // 「不支持的流」分区，等于告诉用户「这条流坏了」，而它没坏。
    val onCardClick = {
        when (
            rtpStreamCardTap(
                codec = stream.codec,
                previewReady = videoMenu.previewReady,
                hasPreviewFile = stream.id in videoMenu.previewStreamIds
            )
        ) {
            RtpStreamCardTap.OpenAudioPlayer -> onOpenPlayer(stream)
            RtpStreamCardTap.OpenVideoPreview -> videoMenu.onPreview(stream)
            // 还没有可播的 MP4：就地封装一份再进预览页（中间产物只写缓存）。
            // 曾经这里是 `onShowDecodableReason(videoNoPreview)`，也就是让用户自己去
            // ⋮ 菜单里导出——但他点的是卡片，不是菜单，那句提示等于把下一步原样退回。
            RtpStreamCardTap.PrepareAndPreview -> onPrepareAndPreview(stream)
        }
    }
    Card(
        modifier = Modifier
            .fillMaxWidth()
            .padding(vertical = 4.dp)
            .border(
                width = 2.dp,
                color = when {
                    selected -> MaterialTheme.colorScheme.primary
                    highlighted -> MaterialTheme.colorScheme.tertiary
                    else -> Color.Transparent
                },
                shape = RoundedCornerShape(12.dp)
            )
    ) {
        Column(
            modifier = Modifier
                .fillMaxWidth()
                .combinedClickable(
                    onClick = {
                        if (selectionMode) {
                            onToggleSelection(stream)
                        } else {
                            onCardClick()
                        }
                    },
                    onLongClick = {
                        if (selectionMode) {
                            onToggleSelection(stream)
                        } else {
                            onEnterSelection(stream)
                        }
                    }
                )
                .padding(horizontal = 12.dp, vertical = 8.dp)
        ) {
            // 端点行：必须永远不把行撑出屏幕。
            Text(
                "${stream.src}:${stream.srcPort} → ${stream.dst}:${stream.dstPort}",
                modifier = Modifier.fillMaxWidth(),
                fontFamily = FontFamily.Monospace,
                style = MaterialTheme.typography.bodySmall,
                maxLines = 1,
                overflow = TextOverflow.Ellipsis
            )

            Row(
                modifier = Modifier.fillMaxWidth().padding(top = 2.dp),
                horizontalArrangement = Arrangement.spacedBy(8.dp),
                verticalAlignment = Alignment.CenterVertically
            ) {
                if (selectionMode) {
                    Checkbox(
                        checked = selected,
                        onCheckedChange = null
                    )
                }
                Text(
                    stringResource(R.string.rtp_stream_ssrc, stream.ssrcHex),
                    modifier = Modifier.weight(1f),
                    fontFamily = FontFamily.Monospace,
                    style = MaterialTheme.typography.labelLarge,
                    maxLines = 1,
                    overflow = TextOverflow.Ellipsis
                )
                if (stream.decodable != RtpDecodability.YES) {
                    DecodableBadge(
                        decodable = stream.decodable,
                        onClick = { onShowDecodableReason(stream.decodableReason) }
                    )
                }
                // RTP1-UI-02 的每流操作菜单。IconButton 自己消费点击事件，
                // 因此点菜单按钮不会同时触发整张卡片的 onCardClick。
                IconButton(
                    onClick = { menuExpanded = true }
                ) {
                    Icon(
                        Icons.Default.MoreVert,
                        contentDescription = stringResource(R.string.rtp_stream_actions)
                    )
                }
                DropdownMenu(
                    expanded = menuExpanded,
                    onDismissRequest = { menuExpanded = false }
                ) {
                    if (rtpStreamIsVideo(stream.codec)) {
                        // RTP5-UI-01：视频流走**另一组**动作，与音频那一组互斥。
                        //
                        // 必须互斥而不是「多几个条目」：RTP5-NAT-01 把可解码判定扩展到了
                        // 视频之后，H.264/H.265/PS 的 `decodable` 都是 `Yes`，照老规则
                        // 「播放」「导出 WAV」「导出格式…」会全部亮着 —— 而音频播放器与导出
                        // 管线里根本没有视频解码器，那三个按钮按下去必然失败。
                        //
                        // `rtpVideoExportFormats` 为空（`PS`：还没解析出真正的编码）时三个
                        // 动作一起置灰，点一下说明原因，而不是给三个按下去同样失败的按钮。
                        val videoExportable = rtpVideoExportFormats(stream.codec).isNotEmpty()
                        val videoActionEnabled = videoExportable && !videoMenu.running
                        val showVideoUnavailable = {
                            menuExpanded = false
                            onShowDecodableReason(videoExportUnavailable)
                        }
                        RtpStreamActionItem(
                            label = stringResource(R.string.rtp_open_external),
                            icon = Icons.Default.PlayArrow,
                            enabled = videoActionEnabled,
                            onClick = {
                                menuExpanded = false
                                videoMenu.onOpenExternal(stream)
                            },
                            onDisabledClick = showVideoUnavailable
                        )
                        RtpStreamActionItem(
                            label = stringResource(R.string.rtp_video_export_mp4),
                            icon = Icons.Default.Download,
                            enabled = videoActionEnabled,
                            onClick = {
                                menuExpanded = false
                                videoMenu.onExport(stream, RtpVideoExportFormat.MP4)
                            },
                            onDisabledClick = showVideoUnavailable
                        )
                        RtpStreamActionItem(
                            label = stringResource(R.string.rtp_video_export_raw),
                            icon = Icons.Default.Download,
                            enabled = videoActionEnabled,
                            onClick = {
                                menuExpanded = false
                                videoMenu.onExport(stream, RtpVideoExportFormat.RAW)
                            },
                            onDisabledClick = showVideoUnavailable
                        )
                        // 「应用内预览」是**有就显示、没有就不显示**（卡片原文），不是置灰：
                        // 它要的是「这份 MP4 现在能播」这个事实，而灰按钮只会让人去猜为什么。
                        if (videoMenu.previewReady && stream.id in videoMenu.previewStreamIds) {
                            RtpStreamActionItem(
                                label = stringResource(R.string.rtp_video_preview_action),
                                icon = Icons.Default.Movie,
                                enabled = true,
                                onClick = {
                                    menuExpanded = false
                                    videoMenu.onPreview(stream)
                                },
                                onDisabledClick = {}
                            )
                        }
                    } else {
                        RtpStreamActionItem(
                            label = stringResource(R.string.rtp_stream_action_play),
                            icon = Icons.Default.PlayArrow,
                            enabled = stream.decodable == RtpDecodability.YES,
                            onClick = {
                                menuExpanded = false
                                onPlayStream(stream)
                            },
                            onDisabledClick = showDecodableReason
                        )
                        RtpStreamActionItem(
                            label = stringResource(R.string.rtp_stream_action_export_wav),
                            icon = Icons.Default.Download,
                            enabled = stream.decodable == RtpDecodability.YES,
                            onClick = {
                                menuExpanded = false
                                onExportWav(stream)
                            },
                            onDisabledClick = showDecodableReason
                        )
                        RtpStreamActionItem(
                            label = stringResource(R.string.rtp_stream_action_export_raw),
                            icon = Icons.Default.Download,
                            enabled = isRawExportable(stream),
                            onClick = {
                                menuExpanded = false
                                onExportRaw(stream)
                            },
                            onDisabledClick = showRawExportReason
                        )
                        // RTP4-KT-03：按编码列出可用格式（WAV / 裸流 / .amr / .awb / .opus）。
                        RtpStreamActionItem(
                            label = stringResource(R.string.rtp_stream_action_export_format),
                            icon = Icons.Default.Download,
                            enabled = rtpExportableFormats(stream).isNotEmpty(),
                            onClick = {
                                menuExpanded = false
                                onExportFormat(stream)
                            },
                            onDisabledClick = showDecodableReason
                        )
                    }
                    DropdownMenuItem(
                        text = {
                            Text(
                                stringResource(R.string.rtp_stream_action_filter),
                                maxLines = 1,
                                overflow = TextOverflow.Ellipsis
                            )
                        },
                        onClick = {
                            menuExpanded = false
                            onFilterStream(stream)
                        }
                    )
                    if (stream.decodable == RtpDecodability.NEEDS_MAPPING ||
                        stream.decodable == RtpDecodability.UNSUPPORTED
                    ) {
                        DropdownMenuItem(
                            text = {
                                Text(
                                    stringResource(R.string.rtp_stream_action_map_codec),
                                    maxLines = 1,
                                    overflow = TextOverflow.Ellipsis
                                )
                            },
                            onClick = {
                                menuExpanded = false
                                onMapCodec(stream)
                            }
                        )
                    }
                }
            }

            val unknown = stringResource(R.string.unknown)
            Row(
                modifier = Modifier.fillMaxWidth().padding(top = 2.dp),
                horizontalArrangement = Arrangement.spacedBy(8.dp),
                verticalAlignment = Alignment.CenterVertically
            ) {
                Text(
                    stringResource(
                        R.string.rtp_stream_codec,
                        stream.codec.ifBlank { unknown },
                        codecSourceLabel(stream.codecSource)
                    ),
                    modifier = Modifier.weight(1f),
                    style = MaterialTheme.typography.bodySmall,
                    maxLines = 1,
                    overflow = TextOverflow.Ellipsis
                )
                // RTP5-UI-01：视频流的「视频」标签。**这里只加标签，不加 MOS** —— 卡片上
                // 本来就没有 MOS（那是 VoIP 呼叫页的逐方向指标），而且视频流在那边也拿不到
                // MOS：`MosEstimator` 只认窄带语音的 Ie 表，H.264/H.265 一律返回 null，
                // 界面于是显示「不适用」（RTP3-KT-03 的口径），不会拿窄带公式硬套。
                if (rtpStreamIsVideo(stream.codec)) VideoBadge()
            }

            Text(
                stringResource(R.string.rtp_stream_packets, stream.packets, stream.expected),
                modifier = Modifier.fillMaxWidth().padding(top = 2.dp),
                style = MaterialTheme.typography.bodySmall,
                color = MaterialTheme.colorScheme.onSurfaceVariant,
                maxLines = 1,
                overflow = TextOverflow.Ellipsis
            )

            Row(
                modifier = Modifier.fillMaxWidth().padding(top = 2.dp),
                horizontalArrangement = Arrangement.spacedBy(8.dp)
            ) {
                Text(
                    stringResource(
                        R.string.rtp_stream_duration,
                        formatOneDecimal(stream.endRel - stream.startRel)
                    ),
                    modifier = Modifier.weight(1f),
                    style = MaterialTheme.typography.bodySmall,
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                    maxLines = 1,
                    overflow = TextOverflow.Ellipsis
                )
                Text(
                    stringResource(R.string.rtp_stream_loss, formatOneDecimal(stream.lostPct)),
                    modifier = Modifier.weight(1f),
                    style = MaterialTheme.typography.bodySmall,
                    color = lossColor(stream.lostPct),
                    maxLines = 1,
                    overflow = TextOverflow.Ellipsis
                )
                Text(
                    jitterText(stream),
                    modifier = Modifier.weight(1f),
                    style = MaterialTheme.typography.bodySmall,
                    color = jitterColor(stream),
                    maxLines = 1,
                    overflow = TextOverflow.Ellipsis
                )
            }
        }
    }
}

@Composable
private fun RtpStreamActionItem(
    label: String,
    icon: ImageVector,
    enabled: Boolean,
    onClick: () -> Unit,
    onDisabledClick: () -> Unit
) {
    val contentColor = if (enabled) {
        MaterialTheme.colorScheme.onSurface
    } else {
        MaterialTheme.colorScheme.onSurfaceVariant.copy(alpha = 0.38f)
    }
    DropdownMenuItem(
        text = {
            Text(
                label,
                color = contentColor,
                maxLines = 1,
                overflow = TextOverflow.Ellipsis
            )
        },
        leadingIcon = {
            Icon(icon, contentDescription = null, tint = contentColor)
        },
        onClick = {
            if (enabled) onClick() else onDisabledClick()
        }
    )
}

/**
 * RTP5-UI-01：「视频」标签。
 *
 * 一个陈述性的标签，不是警告，所以取 `secondary`（中性色）而不是 [decodableBadgeColor] 那
 * 一族的 `tertiary`：一条正常的视频流没有任何问题，它只是不是音频。
 */
@Composable
private fun VideoBadge() {
    val color = MaterialTheme.colorScheme.secondary
    Surface(
        shape = RoundedCornerShape(4.dp),
        color = color.copy(alpha = 0.15f),
        contentColor = color
    ) {
        Text(
            stringResource(R.string.rtp_stream_media_video),
            modifier = Modifier.padding(horizontal = 6.dp, vertical = 2.dp),
            style = MaterialTheme.typography.labelSmall,
            maxLines = 1,
            overflow = TextOverflow.Ellipsis
        )
    }
}

@Composable
private fun DecodableBadge(decodable: RtpDecodability, onClick: () -> Unit) {    val color = decodableBadgeColor(decodable)
    // 用非点击重载 + Modifier.clickable（与 AgentSignalChip 一致），内层点击会消费事件，
    // 因此点徽章不会同时触发整张卡片的 onCardClick。
    Surface(
        shape = RoundedCornerShape(4.dp),
        color = color.copy(alpha = 0.15f),
        contentColor = color,
        modifier = Modifier.clickable { onClick() }
    ) {
        Text(
            decodableLabel(decodable),
            modifier = Modifier.padding(horizontal = 6.dp, vertical = 2.dp),
            style = MaterialTheme.typography.labelSmall,
            maxLines = 1,
            overflow = TextOverflow.Ellipsis
        )
    }
}

@Composable
private fun codecSourceLabel(source: RtpCodecSource): String = when (source) {
    RtpCodecSource.STATIC -> stringResource(R.string.rtp_codec_source_static)
    RtpCodecSource.SDP -> stringResource(R.string.rtp_codec_source_sdp)
    RtpCodecSource.OVERRIDE -> stringResource(R.string.rtp_codec_source_override)
    RtpCodecSource.UNKNOWN -> stringResource(R.string.rtp_codec_source_unknown)
}

@Composable
private fun decodableLabel(decodable: RtpDecodability): String = when (decodable) {
    RtpDecodability.NEEDS_MAPPING -> stringResource(R.string.rtp_decodable_needs_mapping)
    RtpDecodability.SRTP -> stringResource(R.string.rtp_decodable_srtp)
    RtpDecodability.TRUNCATED -> stringResource(R.string.rtp_decodable_truncated)
    else -> stringResource(R.string.rtp_decodable_unsupported)
}

@Composable
private fun decodableBadgeColor(decodable: RtpDecodability): Color = when (decodable) {
    RtpDecodability.SRTP -> MaterialTheme.colorScheme.onSurfaceVariant
    else -> MaterialTheme.colorScheme.tertiary
}

/** 丢包率：<1% 好，1–5% 警告，>5% 差。 */
@Composable
private fun lossColor(lostPct: Double): Color = when {
    lostPct > 5.0 -> MaterialTheme.colorScheme.error
    lostPct >= 1.0 -> MaterialTheme.colorScheme.tertiary
    else -> MaterialTheme.colorScheme.primary
}

/** 抖动：<20ms 好，20–50ms 警告，>50ms 差；不可用时为中性色。 */
@Composable
private fun jitterColor(stream: RtpStream): Color {
    val value = stream.maxJitterMs
    if (!stream.jitterAvailable || value == null) return MaterialTheme.colorScheme.onSurfaceVariant
    return when {
        value > 50.0 -> MaterialTheme.colorScheme.error
        value >= 20.0 -> MaterialTheme.colorScheme.tertiary
        else -> MaterialTheme.colorScheme.primary
    }
}

@Composable
private fun jitterText(stream: RtpStream): String {
    val value = stream.maxJitterMs
    if (!stream.jitterAvailable || value == null) {
        return stringResource(R.string.rtp_jitter_unavailable)
    }
    return stringResource(R.string.rtp_stream_jitter, formatOneDecimal(value))
}

private fun formatOneDecimal(value: Double): String = String.format(Locale.US, "%.1f", value)

// ------------------------------------------------- 指定编码对话框（RTP1-UI-02）

/**
 * 「指定编码」对话框（RTP1-UI-02 补的 KT-04 缺口；RTP4-KT-05 加置灰）。
 *
 * 为何是**公开** composable：冻结的 `onMapCodec: (RtpStream) -> Unit` 只把流交回宿主，
 * 由**宿主**决定何时打开对话框，所以对话框必须独立可调，供 RTP1-UI-03 接线渲染。
 * 本文件（`RtpStreamsScreen`）不自己承载它，以免改变 [RtpStreamsScreen] 的参数语义。
 *
 * 结构参照 `PacketListScreen.kt` 的 `DecodeAsDialog`（`AlertDialog` + 下拉 + `OutlinedTextField`）：
 * 候选来自 [RtpCodecCatalog.entries]；`idSupported == false` 的条目**可选**但标注
 * 「暂不支持解码，选择后仅用于统计」；时钟频率默认取所选条目的 `clockRate`，只有
 * `clockRateEditable == true`（目前仅 AMR-WB）时才能编辑，否则字段禁用。
 *
 * RTP4-KT-05：**这个构建里编不进来的编码置灰**（[DropdownMenuItem] 的 `enabled=false`），
 * 并在标签下注明原因。可用性来自 [RtpCodecCapabilities]，也就是原生的
 * `getRtpCodecCapabilities()`：[capabilities] 传 null 时本对话框自己去取一次
 * （[rememberRtpCodecCapabilities]）；取不到时用 [RtpCodecCapabilities.UNKNOWN]，
 * 一条都不置灰 —— 拿不到列表不该让用户什么都选不了（卡片 §2.5 的 fail-open）。
 * 原因文案与原生 `rtp_decodability_reason()` 说的是同一句话
 * （`rtp_codec_map_unavailable_g729` ↔ 「此构建未包含 G.729」）。
 */
@Composable
fun RtpCodecMapDialog(
    stream: RtpStream,
    onConfirm: (pt: Int, codecId: String, clockRate: Int) -> Unit,
    onDismiss: () -> Unit,
    capabilities: RtpCodecCapabilities? = null
) {
    val initialEntry = remember(stream.id) {
        RtpCodecCatalog.byId(stream.codec) ?: RtpCodecCatalog.entries.first()
    }
    var selected by remember(stream.id) { mutableStateOf(initialEntry) }
    var clockRateText by remember(stream.id) { mutableStateOf(initialEntry.clockRate.toString()) }
    // 宿主给了能力就直接用；没给才去问原生。取回来之前先按 UNKNOWN 渲染
    // （一条都不置灰），所以首帧不会因为异步加载而闪出「全都不可用」。
    val loadedCapabilities = rememberRtpCodecCapabilities(enabled = capabilities == null)
    val effectiveCapabilities =
        capabilities ?: loadedCapabilities ?: RtpCodecCapabilities.UNKNOWN

    AlertDialog(
        onDismissRequest = onDismiss,
        title = {
            Text(
                stringResource(R.string.rtp_codec_map_title, stream.pt),
                maxLines = 1,
                overflow = TextOverflow.Ellipsis
            )
        },
        text = {
            Column(modifier = Modifier.widthIn(max = 560.dp)) {
                CodecPicker(
                    label = stringResource(R.string.rtp_codec_map_codec_label),
                    selected = selected,
                    capabilities = effectiveCapabilities,
                    onSelect = { entry ->
                        selected = entry
                        clockRateText = entry.clockRate.toString()
                    }
                )
                OutlinedTextField(
                    value = clockRateText,
                    onValueChange = { clockRateText = it.filter(Char::isDigit) },
                    label = { Text(stringResource(R.string.rtp_codec_map_clock_rate)) },
                    modifier = Modifier.fillMaxWidth().padding(top = 8.dp),
                    // 只有 AMR-WB 允许编辑；其余为只读（禁用）。
                    enabled = selected.clockRateEditable,
                    singleLine = true
                )
            }
        },
        confirmButton = {
            Button(
                onClick = {
                    val rate = clockRateText.toIntOrNull() ?: selected.clockRate
                    onConfirm(stream.pt, selected.id, rate)
                }
            ) {
                Text(stringResource(R.string.apply))
            }
        },
        dismissButton = {
            TextButton(onClick = onDismiss) {
                Text(stringResource(R.string.cancel))
            }
        }
    )
}

/**
 * 本构建的编码能力，取一次就记住（RTP4-KT-05）。
 *
 * 这是**独立对话框**自己取数据的路径：宿主（`PacketListScreen`）目前还没有把
 * `RtpCodecCapabilities` 传下来，所以 [RtpCodecMapDialog] 用这里兜底。查询是进程级的
 * （不需要会话、不需要打开文件），走 [RtpRepository.codecCapabilities] ——它就是
 * `RtpNativeBridge` 那道缝的写法：一个窄的、可覆盖的仓库方法，解析逻辑留在仓库里。
 *
 * 返回 null 表示还没取回来；[RtpRepository.codecCapabilities] 自己 fail-open，
 * 所以这里不需要再兜一层 `catch`。在 [Dispatchers.IO] 上跑，因为 JNI 调用不能占
 * 组合线程。[enabled] 为 false 时一次原语都不发（宿主已经把它自己的那份传进来了）。
 */
@Composable
private fun rememberRtpCodecCapabilities(enabled: Boolean): RtpCodecCapabilities? {
    var loaded by remember { mutableStateOf<RtpCodecCapabilities?>(null) }
    LaunchedEffect(enabled) {
        if (!enabled) return@LaunchedEffect
        loaded = withContext(Dispatchers.IO) {
            RtpRepository(PacketRepository()).codecCapabilities()
        }
    }
    return loaded
}

/** 编码下拉：样式与 `PacketListScreen.EnumMenu` 一致（`FilterChip` + `DropdownMenu`）。 */
@Composable
private fun CodecPicker(
    label: String,
    selected: RtpCodecCatalog.Entry,
    capabilities: RtpCodecCapabilities,
    onSelect: (RtpCodecCatalog.Entry) -> Unit
) {
    var expanded by remember { mutableStateOf(false) }
    Box {
        FilterChip(
            selected = true,
            onClick = { expanded = true },
            label = {
                Text(
                    "$label: ${selected.label}",
                    maxLines = 1,
                    overflow = TextOverflow.Ellipsis
                )
            }
        )
        DropdownMenu(expanded = expanded, onDismissRequest = { expanded = false }) {
            RtpCodecCatalog.entries.forEach { entry ->
                // 这个构建编不进来的编码（g729 / iLBC）：置灰 + 注明原因。
                // 与 idSupported 是两件事：后者是「App 设计上不支持」，条目仍可选。
                val unavailable = RtpCodecCatalog.unavailableReason(entry.id, capabilities)
                val note = when {
                    unavailable == RtpCodecUnavailableReason.G729_NOT_IN_BUILD ->
                        stringResource(R.string.rtp_codec_map_unavailable_g729)
                    unavailable == RtpCodecUnavailableReason.ILBC_NOT_IN_BUILD ->
                        stringResource(R.string.rtp_codec_map_unavailable_ilbc)
                    !entry.idSupported ->
                        stringResource(R.string.rtp_codec_map_unsupported_note)
                    else -> null
                }
                DropdownMenuItem(
                    enabled = unavailable == null,
                    text = {
                        Column {
                            Text(entry.label, maxLines = 1, overflow = TextOverflow.Ellipsis)
                            if (note != null) {
                                Text(
                                    note,
                                    style = MaterialTheme.typography.bodySmall,
                                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                                    maxLines = 1,
                                    overflow = TextOverflow.Ellipsis
                                )
                            }
                        }
                    },
                    onClick = {
                        expanded = false
                        onSelect(entry)
                    }
                )
            }
        }
    }
}

// ---------------------------------------------------------------- 预览夹具

@Preview(name = "RTP streams · light", showBackground = true, widthDp = 360)
@Composable
private fun RtpStreamsScreenLightPreview() {
    LayerAnalyzerTheme(darkTheme = false) {
        RtpStreamsScreen(
            state = RtpScanUiState.Done(previewScanResult()),
            heuristicEnabled = false,
            onScan = {},
            onCancel = {},
            onToggleHeuristic = {},
            onFilterStream = {},
            onMapCodec = {},
            onBack = {},
            onOpenPlayer = {},
            // RTP5-UI-01：预览里放一条已导出过 MP4 的视频流，这样「视频」标签、
            // 视频那一组菜单项和「应用内预览」都看得见。
            videoPreviewStreamIds = setOf("s3"),
            videoPreviewAvailability = RtpVideoPreviewAvailability.Ready(
                mp4Path = "<rtp cache>/7/1/s3.mp4",
                indexPath = "<rtp cache>/7/1/s3.vidx"
            )
        )
    }
}

@Preview(
    name = "RTP streams · dark",
    showBackground = true,
    widthDp = 360,
    uiMode = Configuration.UI_MODE_NIGHT_YES
)
@Composable
private fun RtpStreamsScreenDarkPreview() {
    LayerAnalyzerTheme(darkTheme = true) {
        RtpStreamsScreen(
            state = RtpScanUiState.Done(previewScanResult()),
            heuristicEnabled = true,
            onScan = {},
            onCancel = {},
            onToggleHeuristic = {},
            onFilterStream = {},
            onMapCodec = {},
            onBack = {},
            onOpenPlayer = {},
            videoPreviewStreamIds = setOf("s3"),
            videoPreviewAvailability = RtpVideoPreviewAvailability.Ready(
                mp4Path = "<rtp cache>/7/1/s3.mp4",
                indexPath = "<rtp cache>/7/1/s3.vidx"
            )
        )
    }
}

private fun previewScanResult(): RtpScanResult = RtpScanResult(
    schemaVersion = 1,
    error = "",
    cancelled = false,
    scanGeneration = 7,
    framesScanned = 12000,
    heuristicEnabled = false,
    streamsTruncated = false,
    streams = listOf(
        RtpStream(
            id = "s0", src = "10.0.0.1", srcPort = 40000, dst = "10.0.0.2", dstPort = 30000,
            ssrc = 439041101L, ssrcHex = "0x1a2b3c4d",
            pt = 8, codec = "g711A", codecSource = RtpCodecSource.STATIC, clockRate = 8000,
            setupFrame = 12L, setupMethod = "SDP", isSrtp = false,
            packets = 1500L, expected = 1503L, lost = 3L, lostPct = 0.2,
            seqErrors = 1L, outOfOrder = 0L, truncated = 0L, problem = false,
            minDeltaMs = 19.4, meanDeltaMs = 20.1, maxDeltaMs = 61.2, maxDeltaFrame = 812L,
            minJitterMs = 0.4, meanJitterMs = 1.3, maxJitterMs = 4.1, jitterAvailable = true,
            maxSkewMs = 2.0, bytes = 192000L,
            firstFrame = 20L, lastFrame = 3100L, startRel = 1.02, endRel = 31.4,
            firstAbsEpochUs = 1_700_000_000_000_000L,
            ptsSeen = listOf(8, 101), decodable = RtpDecodability.YES, decodableReason = "",
            primaryPayloadType = 8
        ),
        RtpStream(
            id = "s1", src = "2001:db8::1", srcPort = 50000, dst = "2001:db8::2", dstPort = 50002,
            ssrc = 305419896L, ssrcHex = "0x12345678",
            pt = 96, codec = "", codecSource = RtpCodecSource.UNKNOWN, clockRate = 0,
            setupFrame = 42L, setupMethod = "", isSrtp = false,
            packets = 900L, expected = 940L, lost = 40L, lostPct = 4.3,
            seqErrors = 6L, outOfOrder = 2L, truncated = 4L, problem = true,
            minDeltaMs = 18.0, meanDeltaMs = 24.6, maxDeltaMs = 120.7, maxDeltaFrame = 512L,
            minJitterMs = null, meanJitterMs = null, maxJitterMs = null, jitterAvailable = false,
            maxSkewMs = 5.5, bytes = 63000L,
            firstFrame = 60L, lastFrame = 9000L, startRel = 3.5, endRel = 45.2,
            firstAbsEpochUs = 1_700_000_000_000_000L,
            ptsSeen = listOf(96),
            decodable = RtpDecodability.NEEDS_MAPPING,
            decodableReason = "Dynamic payload type 96 has no SDP mapping.",
            primaryPayloadType = 96
        ),
        RtpStream(
            id = "s2", src = "203.0.113.9", srcPort = 6000, dst = "198.51.100.7", dstPort = 6001,
            ssrc = 2726625545L, ssrcHex = "0xa28f4c09",
            pt = 111, codec = "opus", codecSource = RtpCodecSource.SDP, clockRate = 48000,
            setupFrame = 5L, setupMethod = "SDP", isSrtp = true,
            packets = 2400L, expected = 2400L, lost = 0L, lostPct = 0.0,
            seqErrors = 0L, outOfOrder = 0L, truncated = 0L, problem = false,
            minDeltaMs = 19.8, meanDeltaMs = 20.0, maxDeltaMs = 65.9, maxDeltaFrame = 1500L,
            minJitterMs = 1.1, meanJitterMs = 2.7, maxJitterMs = 63.4, jitterAvailable = true,
            maxSkewMs = 1.2, bytes = 240000L,
            firstFrame = 80L, lastFrame = 5100L, startRel = 4.1, endRel = 60.0,
            firstAbsEpochUs = 1_700_000_000_000_000L,
            ptsSeen = listOf(111), decodable = RtpDecodability.SRTP,
            decodableReason = "SRTP payload is encrypted and cannot be decoded.",
            primaryPayloadType = 111
        ),
        // RTP5-UI-01 的预览夹具：一条 H.264 视频流（原生的 `rtp_decodability()` 对
        // `kSupportedVideoCodecs` 回 `Yes`，所以它在这里也是 YES —— 卡片因此必须自己把它
        // 分流到视频那一组菜单，而不是照着 `decodable` 摆出「播放」和「导出 WAV」）。
        RtpStream(
            id = "s3", src = "10.0.0.1", srcPort = 40002, dst = "10.0.0.2", dstPort = 40003,
            ssrc = 1094861636L, ssrcHex = "0x41424344",
            pt = 102, codec = "H264", codecSource = RtpCodecSource.SDP, clockRate = 90000,
            setupFrame = 12L, setupMethod = "SDP", isSrtp = false,
            packets = 3600L, expected = 3603L, lost = 3L, lostPct = 0.1,
            seqErrors = 0L, outOfOrder = 0L, truncated = 0L, problem = false,
            minDeltaMs = 32.0, meanDeltaMs = 33.3, maxDeltaMs = 70.0, maxDeltaFrame = 2000L,
            minJitterMs = 0.5, meanJitterMs = 1.1, maxJitterMs = 3.2, jitterAvailable = true,
            maxSkewMs = 3.0, bytes = 5_400_000L,
            firstFrame = 20L, lastFrame = 8000L, startRel = 1.02, endRel = 121.0,
            firstAbsEpochUs = 1_700_000_000_000_000L,
            ptsSeen = listOf(102), decodable = RtpDecodability.YES, decodableReason = "",
            primaryPayloadType = 102
        )
    )
)
