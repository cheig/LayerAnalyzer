package com.example.layanalyzer.ui.components.rtp

import android.net.Uri
import androidx.activity.compose.BackHandler
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.BoxWithConstraints
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.ExperimentalLayoutApi
import androidx.compose.foundation.layout.FlowRow
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.RowScope
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.offset
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.layout.widthIn
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.foundation.verticalScroll
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.automirrored.filled.ArrowBack
import androidx.compose.material.icons.automirrored.filled.OpenInNew
import androidx.compose.material.icons.filled.Download
import androidx.compose.material.icons.filled.ExpandLess
import androidx.compose.material.icons.filled.ExpandMore
import androidx.compose.material.icons.filled.Pause
import androidx.compose.material.icons.filled.PlayArrow
import androidx.compose.material.icons.filled.Refresh
import androidx.compose.material.icons.filled.Share
import androidx.compose.material3.Button
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.FilterChip
import androidx.compose.material3.HorizontalDivider
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.LinearProgressIndicator
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.Scaffold
import androidx.compose.material3.ScrollableTabRow
import androidx.compose.material3.SnackbarHost
import androidx.compose.material3.SnackbarHostState
import androidx.compose.material3.Surface
import androidx.compose.material3.Switch
import androidx.compose.material3.Tab
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.material3.TopAppBar
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.rememberCoroutineScope
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.platform.LocalDensity
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.style.TextAlign
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.IntOffset
import androidx.compose.ui.unit.dp
import com.example.layanalyzer.R
import com.example.layanalyzer.data.FrameMapFile
import com.example.layanalyzer.data.PeaksFile
import com.example.layanalyzer.data.frameAt
import com.example.layanalyzer.media.ExternalPlayerLauncher
import com.example.layanalyzer.media.RtpPlayerState
import com.example.layanalyzer.model.RtpDtmfEvent
import com.example.layanalyzer.model.RtpEvent
import com.example.layanalyzer.model.RtpExportFormat
import com.example.layanalyzer.model.RtpGap
import com.example.layanalyzer.model.RtpStream
import com.example.layanalyzer.model.RtpTimingMode
import com.example.layanalyzer.model.RtpUnsupportedReason
import com.example.layanalyzer.model.RtpUnsupportedStream
import com.example.layanalyzer.model.rtpWavFileName
import com.example.layanalyzer.viewmodel.RtpDualTrackPlayback
import com.example.layanalyzer.viewmodel.RtpExportUiState
import com.example.layanalyzer.viewmodel.RtpExternalOpenUiState
import com.example.layanalyzer.viewmodel.RtpPlayerDecodeStatus
import com.example.layanalyzer.viewmodel.RtpPlayerTrackSource
import com.example.layanalyzer.viewmodel.RtpPlayerUiState
import com.example.layanalyzer.viewmodel.RtpTrackMuteState
import java.io.File
import java.util.Locale
import kotlin.math.roundToInt
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext

/** Formats one player position as `mm:ss.S`. */
internal fun formatRtpPlayerTime(positionMs: Long): String {
    val totalTenths = positionMs.coerceAtLeast(0L) / 100L
    val minutes = totalTenths / 600L
    val seconds = (totalTenths / 10L) % 60L
    val tenths = totalTenths % 10L
    return String.format(Locale.US, "%02d:%02d.%d", minutes, seconds, tenths)
}

/**
 * 一条轨道对齐到共享时间轴之后的渲染数据（RTP3-UI-03）。
 *
 * [shiftBuckets] 只用于自检与单测；真正参与绘制的是补过静音的 [peaks] 和换算过采样率的
 * [samplesPerBucket]。
 */
internal data class RtpAlignedTrack(
    val peaks: ShortArray,
    val samplesPerBucket: Int,
    val shiftBuckets: Int
)

/**
 * 把一条轨道对齐到混音的共享时间轴（RTP3-UI-03）。
 *
 * 原生层只给一份**已对齐**的立体声 `mix.wav`，两条单声道轨道的 peaks 都是各自从本流首包开始
 * 的（`RtpJni.cpp` 里 `mix.peaksLeftPath` 就是该流自己的 `peaks_path`，没有前置静音）。
 * 共享轴上该轨道自身的时间 `t` 落在 `offsetMs + t`，所以在 peaks 前面补 `offsetMs` 对应的
 * 静音桶——peaks 是 min/max 交错的 short 数组，一桶 2 个 short，补零即补静音。
 *
 * 同时把桶大小换算到 [mainSampleRate]：`RtpWaveform` 用**主轨的** `sampleRate` 配合各轨自己的
 * `samplesPerBucket` 换算每桶时长（见 `drawWaveformTrack`），两轨采样率不同时不换算就会把第二
 * 条轨道的时间轴画错。采样率相同时换算是恒等变换。
 *
 * @param offsetMs 该轨道在共享轴上的前置静音时长（`RtpMixResult.leftOffsetMs` / `rightOffsetMs`）
 * @param mainSampleRate 主轨（左声道）的采样率，也是传给 `RtpWaveform` 的 `sampleRate`
 */
internal fun rtpAlignTrackToSharedAxis(
    peaks: ShortArray,
    samplesPerBucket: Int,
    sampleRate: Int,
    offsetMs: Long,
    mainSampleRate: Int
): RtpAlignedTrack {
    val scaled = rtpScaledSamplesPerBucket(samplesPerBucket, sampleRate, mainSampleRate)
    // 桶大小或采样率缺失时**不补零**：那会把「一桶多少毫秒」猜成一个错的值，宁可让这条轨道
    // 从头开始画，也不能把它摆到一个算出来的错误位置上。
    val canAlign = peaks.isNotEmpty() && offsetMs > 0L &&
        samplesPerBucket > 0 && sampleRate > 0 && mainSampleRate > 0
    if (!canAlign) return RtpAlignedTrack(peaks, scaled, 0)

    val bucketMicros = scaled.toLong() * 1_000_000L / mainSampleRate.toLong()
    if (bucketMicros <= 0L) return RtpAlignedTrack(peaks, scaled, 0)

    // 四舍五入到最近的桶：误差不超过半个桶，比向下取整更接近原生层的真实偏移。
    // 先把 offsetMs 夹到上限再乘 1000——极端值下 `offsetMs * 1000` 本身就会溢出 Long。
    val maxBuckets = RTP_MAX_SHIFT_BUCKETS.toLong()
    val boundedMs = offsetMs.coerceAtMost(maxBuckets * bucketMicros / 1000L + 1L)
    val shift = ((boundedMs * 1000L + bucketMicros / 2) / bucketMicros)
        .coerceIn(0L, maxBuckets)
        .toInt()
    if (shift == 0) return RtpAlignedTrack(peaks, scaled, 0)

    val padding = shift * 2
    val padded = ShortArray(padding + peaks.size)
    peaks.copyInto(padded, padding)
    return RtpAlignedTrack(padded, scaled, shift)
}

/** 单轨自身时间 → 共享轴时间。 */
internal fun rtpSharedAxisMs(ownMs: Long, offsetMs: Long): Long =
    ownMs.coerceAtLeast(0L) + offsetMs.coerceAtLeast(0L)

/** 共享轴时间 → 单轨自身时间（要按该轨自己的 map 取帧号，必须先换回去）。 */
internal fun rtpTrackLocalMs(sharedMs: Long, offsetMs: Long): Long =
    (sharedMs - offsetMs).coerceAtLeast(0L)

/** 把一条轨道的 gap 平移到共享轴。 */
internal fun rtpShiftGaps(gaps: List<RtpGap>, offsetMs: Long): List<RtpGap> =
    if (offsetMs <= 0L) gaps else gaps.map { it.copy(atMs = rtpSharedAxisMs(it.atMs, offsetMs)) }

/** 把一条轨道的 events 平移到共享轴。 */
internal fun rtpShiftEvents(events: List<RtpEvent>, offsetMs: Long): List<RtpEvent> =
    if (offsetMs <= 0L) events else events.map { it.copy(atMs = rtpSharedAxisMs(it.atMs, offsetMs)) }

/**
 * RFC 4733 DTMF 事件在共享轴上的标记（RTP3-UI-03）。
 *
 * 直接复用 `RtpWaveform` 的 events 标记通道，数字放在 `value` 里；标记本身写不下数字，
 * 可点击的数字标签由播放器页自己的标签行给出。
 */
internal fun rtpDtmfEvents(dtmf: List<RtpDtmfEvent>, offsetMs: Long): List<RtpEvent> =
    dtmf.map { event ->
        RtpEvent(
            atMs = rtpSharedAxisMs(event.atMs, offsetMs),
            type = RTP_DTMF_EVENT_TYPE,
            value = event.digit,
            frame = event.frame
        )
    }

/**
 * 把一条轨道的桶大小换算到 [mainSampleRate] 下的等价桶（保证每桶的时长不变）。
 *
 * 参数非法时返回 1：调用方宁可画一根粗糙的波形，也不能拿 0 去除。
 */
private fun rtpScaledSamplesPerBucket(
    samplesPerBucket: Int,
    sampleRate: Int,
    mainSampleRate: Int
): Int {
    if (samplesPerBucket <= 0 || sampleRate <= 0 || mainSampleRate <= 0) return 1
    return (samplesPerBucket.toLong() * mainSampleRate / sampleRate)
        .coerceIn(1L, Int.MAX_VALUE.toLong())
        .toInt()
}

/**
 * RTP2-UI-02 player screen.
 *
 * The ViewModel owns decoding and playback state. This composable only reads
 * cached peaks/map files and delegates actions to the host.
 */
@OptIn(ExperimentalMaterial3Api::class, ExperimentalLayoutApi::class)
@Composable
fun RtpPlayerScreen(
    state: RtpPlayerUiState,
    playbackState: RtpPlayerState,
    positionMs: Long,
    exportState: RtpExportUiState,
    onBack: () -> Unit,
    onPlayPause: () -> Unit,
    onSeek: (Long) -> Unit,
    onTimingChange: (RtpTimingMode) -> Unit,
    onCancelDecode: () -> Unit,
    onRetryDecode: () -> Unit,
    onSelectStream: (String) -> Unit = {},
    onPacketClick: (Long) -> Unit,
    onExportWav: (Uri) -> Unit,
    onShareWav: () -> Unit,
    onClearExportState: () -> Unit,
    /**
     * RTP4-KT-03「外部打开」的容器准备状态。宿主（`RtpViewModel.prepareExternalOpen`）
     * 把流导出成原生容器后发布 [RtpExternalOpenUiState.Ready]，本屏幕按「容器 → WAV」
     * 的顺序打开；容器没有应用能处理时用 WAV 回退并提示。
     */
    externalOpenState: RtpExternalOpenUiState = RtpExternalOpenUiState.Idle,
    onOpenExternal: (RtpStream) -> Unit = {},
    onClearExternalOpenState: () -> Unit = {}
) {
    val context = LocalContext.current
    val scope = rememberCoroutineScope()
    val snackbarHostState = remember { SnackbarHostState() }
    val selectedStream = state.selectedStream
    val selectedItem = state.selectedItem
    val durationMs = selectedItem?.durationMs?.coerceAtLeast(0L) ?: 0L
    val canUseMedia = state.status == RtpPlayerDecodeStatus.READY && selectedItem != null
    val exportRunning = exportState is RtpExportUiState.Running

    var waveformData by remember(selectedItem?.peaksPath, selectedItem?.mapPath) {
        mutableStateOf<RtpWaveformData?>(null)
    }
    LaunchedEffect(selectedItem?.peaksPath, selectedItem?.mapPath) {
        waveformData = null
        val item = selectedItem ?: return@LaunchedEffect
        waveformData = withContext(Dispatchers.IO) {
            runCatching {
                val (header, peaks) = PeaksFile.read(File(item.peaksPath))
                RtpWaveformData(
                    header = header,
                    peaks = peaks,
                    frameMap = FrameMapFile.read(File(item.mapPath))
                )
            }.getOrNull()
        }
    }

    val exportComplete = stringResource(R.string.rtp_player_export_complete)
    val exportFailed = stringResource(R.string.rtp_player_export_failed)
    val shareChooserOpened = stringResource(R.string.rtp_player_share_opened)
    val shareFailed = stringResource(R.string.rtp_player_share_failed)
    val noPlayerApp = stringResource(R.string.rtp_no_player_app)
    val noPlayerAppForFormat = stringResource(R.string.rtp_no_player_app_format)
    val wavFallbackNotice = stringResource(R.string.rtp_open_external_wav_fallback)
    LaunchedEffect(exportState) {
        when (val current = exportState) {
            RtpExportUiState.Idle,
            is RtpExportUiState.Running -> Unit

            is RtpExportUiState.Error -> {
                snackbarHostState.showSnackbar(current.message.ifBlank { exportFailed })
                onClearExportState()
            }

            is RtpExportUiState.Finished -> {
                val shareResults = current.shareResults
                if (shareResults.isNotEmpty()) {
                    val message = runCatching {
                        shareRtpExportResults(context, shareResults)
                    }.fold(
                        onSuccess = { shareChooserOpened },
                        onFailure = { it.message ?: shareFailed }
                    )
                    snackbarHostState.showSnackbar(message)
                } else if (current.summary.failures.isNotEmpty()) {
                    snackbarHostState.showSnackbar(
                        current.summary.failures.first().message.ifBlank { exportFailed }
                    )
                } else {
                    snackbarHostState.showSnackbar(exportComplete)
                }
                onClearExportState()
            }
        }
    }

    val exportLauncher = rememberRtpWavExportLauncher { uri ->
        if (uri != null) onExportWav(uri)
    }

    // RTP4-KT-03 卡片第 2 条：容器优先，`open` 返回 false（没有应用能处理该 MIME）
    // 时用已经渲染好的 WAV 回退。WAV 的 MIME 取 RtpExportFormat.WAV，与
    // `RtpViewModel` 写进 ExportResult 的取值是同一处。
    LaunchedEffect(externalOpenState) {
        when (val current = externalOpenState) {
            RtpExternalOpenUiState.Idle,
            is RtpExternalOpenUiState.Preparing -> Unit

            is RtpExternalOpenUiState.Error -> {
                snackbarHostState.showSnackbar(current.message.ifBlank { exportFailed })
                onClearExternalOpenState()
            }

            is RtpExternalOpenUiState.Ready -> {
                val wav = selectedItem?.wavPath?.takeIf(String::isNotBlank)
                val candidates = buildList {
                    current.containerPath.takeIf(String::isNotBlank)?.let { path ->
                        add(
                            ExternalPlayerLauncher.ExternalOpenCandidate(
                                file = File(path),
                                mimeType = current.mimeType
                            )
                        )
                    }
                    wav?.let { path ->
                        add(
                            ExternalPlayerLauncher.ExternalOpenCandidate(
                                file = File(path),
                                mimeType = RtpExportFormat.WAV.mimeType
                            )
                        )
                    }
                }
                val opened = runCatching {
                    ExternalPlayerLauncher.openFirstAvailable(context, candidates)
                }.getOrNull()
                val hasContainer = current.containerPath.isNotBlank()
                val message = when {
                    opened == null -> if (hasContainer) noPlayerAppForFormat else noPlayerApp
                    hasContainer && opened.mimeType == RtpExportFormat.WAV.mimeType ->
                        wavFallbackNotice

                    else -> null
                }
                if (message != null) snackbarHostState.showSnackbar(message)
                onClearExternalOpenState()
            }
        }
    }

    BackHandler(onBack = onBack)

    Scaffold(
        topBar = {
            TopAppBar(
                title = {
                    Text(
                        text = selectedStream?.let {
                            stringResource(
                                R.string.rtp_player_stream_identity,
                                it.src,
                                it.srcPort,
                                it.dst,
                                it.dstPort
                            )
                        } ?: stringResource(R.string.rtp_player_title),
                        maxLines = 1,
                        overflow = TextOverflow.Ellipsis
                    )
                },
                navigationIcon = {
                    IconButton(onClick = onBack) {
                        Icon(
                            Icons.AutoMirrored.Filled.ArrowBack,
                            contentDescription = stringResource(R.string.back)
                        )
                    }
                },
                actions = {
                    IconButton(
                        enabled = canUseMedia && externalOpenState !is RtpExternalOpenUiState.Preparing,
                        onClick = {
                            // RTP4-KT-03：先让宿主把容器导出来（AMR/AMR-WB/Opus），
                            // 结果由上面的 LaunchedEffect 按「容器 → WAV」打开。
                            selectedStream?.let(onOpenExternal)
                        }
                    ) {
                        Icon(
                            Icons.AutoMirrored.Filled.OpenInNew,
                            contentDescription = stringResource(R.string.rtp_open_external)
                        )
                    }
                    IconButton(
                        enabled = canUseMedia && !exportRunning,
                        onClick = {
                            val stream = selectedStream ?: return@IconButton
                            exportLauncher.launch(rtpWavExportFileName(stream))
                        }
                    ) {
                        Icon(
                            Icons.Default.Download,
                            contentDescription = stringResource(R.string.export)
                        )
                    }
                    IconButton(
                        enabled = canUseMedia && !exportRunning,
                        onClick = onShareWav
                    ) {
                        Icon(
                            Icons.Default.Share,
                            contentDescription = stringResource(R.string.rtp_player_share)
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
                .verticalScroll(rememberScrollState())
                .padding(horizontal = 16.dp, vertical = 12.dp)
        ) {
            if (state.streams.size > 1) {
                val selectedIndex = state.streams
                    .indexOfFirst { it.id == state.selectedStreamId }
                    .coerceAtLeast(0)
                ScrollableTabRow(
                    selectedTabIndex = selectedIndex,
                    edgePadding = 0.dp,
                    modifier = Modifier.fillMaxWidth()
                ) {
                    state.streams.forEach { stream ->
                        Tab(
                            selected = stream.id == state.selectedStreamId,
                            onClick = { onSelectStream(stream.id) },
                            modifier = Modifier.widthIn(min = 140.dp, max = 260.dp),
                            text = {
                                Text(
                                    stringResource(
                                        R.string.rtp_player_stream_identity,
                                        stream.src,
                                        stream.srcPort,
                                        stream.dst,
                                        stream.dstPort
                                    ),
                                    maxLines = 1,
                                    overflow = TextOverflow.Ellipsis
                                )
                            }
                        )
                    }
                }
                Spacer(modifier = Modifier.height(8.dp))
            }

            TimingSelector(
                selected = state.timing,
                enabled = selectedStream != null,
                onSelect = onTimingChange
            )

            when (state.status) {
                RtpPlayerDecodeStatus.IDLE,
                RtpPlayerDecodeStatus.DECODING -> DecodeProgress(
                    state = state,
                    onCancel = onCancelDecode
                )

                RtpPlayerDecodeStatus.ERROR -> DecodeMessage(
                    message = state.errorMessage ?: stringResource(R.string.rtp_player_decode_failed),
                    actionLabel = stringResource(R.string.retry),
                    onAction = onRetryDecode,
                    isError = true
                )

                RtpPlayerDecodeStatus.CANCELLED -> DecodeMessage(
                    message = stringResource(R.string.rtp_player_decode_cancelled),
                    actionLabel = stringResource(R.string.retry),
                    onAction = onRetryDecode,
                    isError = false
                )

                RtpPlayerDecodeStatus.READY -> {
                    if (selectedItem != null) {
                        val waveform = waveformData
                        RtpWaveform(
                            peaks = waveform?.peaks ?: ShortArray(0),
                            sampleRate = waveform?.header?.sampleRate ?: selectedItem.sampleRate,
                            samplesPerBucket = waveform?.header?.samplesPerBucket ?: 1,
                            durationMs = durationMs,
                            gaps = selectedItem.gaps,
                            events = selectedItem.events,
                            playheadMs = positionMs.coerceIn(0L, durationMs),
                            onSeek = onSeek,
                            modifier = Modifier
                                .fillMaxWidth()
                                .height(144.dp)
                        )
                        PlaybackControls(
                            playbackState = playbackState,
                            positionMs = positionMs,
                            durationMs = durationMs,
                            onPlayPause = onPlayPause
                        )
                        val currentFrame = waveform?.let {
                            FrameMapFile.frameAt(positionMs, it.frameMap)
                        }
                        Row(
                            modifier = Modifier
                                .fillMaxWidth()
                                .padding(top = 4.dp),
                            verticalAlignment = Alignment.CenterVertically
                        ) {
                            Text(
                                text = currentFrame?.let {
                                    stringResource(R.string.rtp_player_current_frame, it)
                                } ?: stringResource(R.string.rtp_player_frame_unavailable),
                                modifier = Modifier.weight(1f),
                                style = MaterialTheme.typography.bodyMedium,
                                maxLines = 1,
                                overflow = TextOverflow.Ellipsis
                            )
                            TextButton(
                                enabled = currentFrame != null,
                                onClick = { currentFrame?.let(onPacketClick) }
                            ) {
                                Text(stringResource(R.string.rtp_player_jump_to_packet))
                            }
                        }
                        HorizontalDivider(modifier = Modifier.padding(vertical = 8.dp))
                        PlayerInfo(item = selectedItem)
                    }
                }
            }

            if (state.unsupported.isNotEmpty()) {
                HorizontalDivider(modifier = Modifier.padding(vertical = 12.dp))
                Text(
                    stringResource(R.string.rtp_player_unsupported_title),
                    style = MaterialTheme.typography.titleMedium
                )
                state.unsupported.forEach { unsupported ->
                    Column(modifier = Modifier.padding(top = 8.dp)) {
                        Text(
                            stringResource(
                                R.string.rtp_player_unsupported_stream,
                                unsupported.streamId
                            ),
                            fontFamily = FontFamily.Monospace,
                            style = MaterialTheme.typography.bodyMedium
                        )
                        Text(
                            unsupportedReasonText(unsupported.reason),
                            style = MaterialTheme.typography.bodySmall,
                            color = MaterialTheme.colorScheme.onSurfaceVariant
                        )
                    }
                }
            }

            if (exportRunning) {
                Spacer(modifier = Modifier.height(12.dp))
                val progress = (exportState as? RtpExportUiState.Running)?.progress
                if (progress != null && progress.total > 0) {
                    LinearProgressIndicator(
                        progress = {
                            (progress.done.toFloat() / progress.total.toFloat()).coerceIn(0f, 1f)
                        },
                        modifier = Modifier.fillMaxWidth()
                    )
                } else {
                    LinearProgressIndicator(modifier = Modifier.fillMaxWidth())
                }
            }
        }
    }
}

@OptIn(ExperimentalLayoutApi::class)
@Composable
private fun TimingSelector(
    selected: RtpTimingMode,
    enabled: Boolean,
    onSelect: (RtpTimingMode) -> Unit
) {
    FlowRow(
        horizontalArrangement = Arrangement.spacedBy(8.dp),
        verticalArrangement = Arrangement.spacedBy(4.dp)
    ) {
        RtpTimingMode.entries.forEach { timing ->
            FilterChip(
                selected = selected == timing,
                enabled = enabled,
                onClick = { onSelect(timing) },
                label = { Text(rtpTimingLabel(timing)) }
            )
        }
    }
}

@Composable
private fun DecodeProgress(
    state: RtpPlayerUiState,
    onCancel: () -> Unit
) {
    val progress = state.progress
    Column(modifier = Modifier.padding(top = 16.dp)) {
        Text(
            stringResource(R.string.rtp_player_decoding),
            style = MaterialTheme.typography.bodyMedium
        )
        if (progress != null && progress.total > 0) {
            Text(
                stringResource(R.string.rtp_scan_progress, progress.done, progress.total),
                modifier = Modifier.padding(top = 4.dp),
                style = MaterialTheme.typography.bodySmall,
                color = MaterialTheme.colorScheme.onSurfaceVariant
            )
            LinearProgressIndicator(
                progress = {
                    (progress.done.toFloat() / progress.total.toFloat()).coerceIn(0f, 1f)
                },
                modifier = Modifier
                    .fillMaxWidth()
                    .padding(top = 8.dp)
            )
        } else {
            LinearProgressIndicator(
                modifier = Modifier
                    .fillMaxWidth()
                    .padding(top = 8.dp)
            )
        }
        Button(
            onClick = onCancel,
            modifier = Modifier.padding(top = 12.dp)
        ) {
            Text(stringResource(R.string.cancel))
        }
    }
}

@Composable
private fun DecodeMessage(
    message: String,
    actionLabel: String,
    onAction: () -> Unit,
    isError: Boolean
) {
    Column(modifier = Modifier.padding(top = 16.dp)) {
        Text(
            message,
            color = if (isError) MaterialTheme.colorScheme.error
            else MaterialTheme.colorScheme.onSurfaceVariant
        )
        Button(
            onClick = onAction,
            modifier = Modifier.padding(top = 12.dp)
        ) {
            Icon(Icons.Default.Refresh, contentDescription = null)
            Spacer(modifier = Modifier.width(8.dp))
            Text(actionLabel)
        }
    }
}

@Composable
private fun PlaybackControls(
    playbackState: RtpPlayerState,
    positionMs: Long,
    durationMs: Long,
    onPlayPause: () -> Unit
) {
    val isPlaying = playbackState == RtpPlayerState.Playing
    Row(
        modifier = Modifier
            .fillMaxWidth()
            .padding(top = 8.dp),
        verticalAlignment = Alignment.CenterVertically
    ) {
        IconButton(
            onClick = onPlayPause,
            enabled = playbackState !is RtpPlayerState.Error
        ) {
            Icon(
                imageVector = if (isPlaying) Icons.Default.Pause else Icons.Default.PlayArrow,
                contentDescription = stringResource(
                    if (isPlaying) R.string.rtp_player_pause else R.string.rtp_player_play
                )
            )
        }
        Text(
            text = formatRtpPlayerTime(positionMs),
            fontFamily = FontFamily.Monospace,
            style = MaterialTheme.typography.bodyMedium
        )
        Text(
            text = " / ${formatRtpPlayerTime(durationMs)}",
            fontFamily = FontFamily.Monospace,
            style = MaterialTheme.typography.bodyMedium,
            color = MaterialTheme.colorScheme.onSurfaceVariant
        )
        Spacer(modifier = Modifier.weight(1f))
    }
    playbackState.errorMessageOrNull()?.let { message ->
        Text(
            text = message,
            modifier = Modifier.padding(top = 4.dp),
            color = MaterialTheme.colorScheme.error,
            style = MaterialTheme.typography.bodySmall
        )
    }
}

@Composable
private fun PlayerInfo(item: com.example.layanalyzer.model.RtpDecodedItem) {
    Text(
        stringResource(R.string.rtp_player_info_title),
        style = MaterialTheme.typography.titleMedium
    )
    InfoRow(stringResource(R.string.rtp_player_codec), item.codec)
    InfoRow(stringResource(R.string.rtp_player_sample_rate), "${item.sampleRate} Hz")
    InfoRow(stringResource(R.string.rtp_player_lost), item.stats.lost.toString())
    InfoRow(stringResource(R.string.rtp_player_dropped_late), item.stats.droppedLate.toString())
    InfoRow(
        stringResource(R.string.rtp_player_truncated),
        item.stats.truncatedPackets.toString()
    )
}

@Composable
private fun InfoRow(label: String, value: String) {
    Row(
        modifier = Modifier
            .fillMaxWidth()
            .padding(top = 6.dp)
    ) {
        Text(
            text = label,
            modifier = Modifier.weight(0.45f),
            color = MaterialTheme.colorScheme.onSurfaceVariant,
            style = MaterialTheme.typography.bodyMedium
        )
        Text(
            text = value,
            modifier = Modifier.weight(0.55f),
            style = MaterialTheme.typography.bodyMedium,
            maxLines = 1,
            overflow = TextOverflow.Ellipsis
        )
    }
}

@Composable
private fun rtpTimingLabel(timing: RtpTimingMode): String = when (timing) {
    RtpTimingMode.JITTER -> stringResource(R.string.rtp_timing_jitter)
    RtpTimingMode.RTP_TIMESTAMP -> stringResource(R.string.rtp_timing_rtp_timestamp)
    RtpTimingMode.UNINTERRUPTED -> stringResource(R.string.rtp_timing_uninterrupted)
}

@Composable
private fun unsupportedReasonText(reason: String): String {
    val unknown = stringResource(R.string.unknown)
    return when (RtpUnsupportedReason.fromWire(reason)) {
        RtpUnsupportedReason.SRTP -> stringResource(R.string.rtp_unsupported_srtp)
        RtpUnsupportedReason.NEEDS_MAPPING ->
            stringResource(R.string.rtp_unsupported_needs_mapping)
        RtpUnsupportedReason.UNSUPPORTED ->
            stringResource(R.string.rtp_unsupported_codec)
        RtpUnsupportedReason.STALE_SCAN ->
            stringResource(R.string.rtp_unsupported_stale_scan)
        RtpUnsupportedReason.NOT_FOUND ->
            stringResource(R.string.rtp_unsupported_not_found)
        null -> reason.ifBlank { unknown }
    }
}

private fun RtpPlayerState.errorMessageOrNull(): String? =
    (this as? RtpPlayerState.Error)?.message

// --------------------------------------------------------------- RTP3-UI-03 双轨播放器

/** 双轨播放器里被选中的轨道；决定「跳到数据包」用哪一份帧映射。 */
private enum class RtpPlayerTrackSide { LEFT, RIGHT }

/** 共享轴上的一条 DTMF 事件（数字 + 归属轨道），时间轴标签与列表共用。 */
private data class RtpSharedDtmf(
    val digit: String,
    val atMs: Long,
    val durMs: Long,
    val frame: Long,
    val side: RtpPlayerTrackSide
)

/** 一次待执行的导出：SAF 只回一个 URI，源文件和文件名必须在发起时就记下来。 */
private data class RtpDualTrackExport(val filePath: String, val displayName: String)

/** 一条轨道读盘后的渲染数据（peaks + 帧映射）。 */
private data class RtpTrackRenderData(
    val peaks: ShortArray,
    val samplesPerBucket: Int,
    val sampleRate: Int,
    val frameMap: List<FrameMapFile.Entry>
)

/** 一次 [readTrackRenderData] 的结果；任一轨道读失败时整体为 null。 */
private data class RtpDualTrackRenderData(
    val left: RtpTrackRenderData?,
    val right: RtpTrackRenderData?
)

/**
 * RTP3-UI-03 双向播放器。
 *
 * 两条波形共用同一时间轴与同一播放头：主轨传给 [RtpWaveform]，右声道作为 `extraTracks`，
 * 两条轨道的 peaks 各自按 [com.example.layanalyzer.viewmodel.RtpPlayerTrackSource.offsetMs]
 * 补上前置静音（见 [rtpAlignTrackToSharedAxis]），所以上下两条波形与同一个播放头是对齐的。
 *
 * 与 M2 的单轨 [RtpPlayerScreen] **完全独立**：这里不调用它、不修改它，也不改动它依赖的任何
 * 组件行为——M2 的退出门禁不受影响。
 *
 * @param title 顶栏标题（宿主给的「主叫 → 被叫」或呼叫标识）
 * @param playback 轨道输入；`null` 表示解码还没结束
 * @param errorMessage 解码失败原因；非空时优先显示失败态
 * @param unsupported 原生层报告的不支持流
 */
@OptIn(ExperimentalMaterial3Api::class, ExperimentalLayoutApi::class)
@Composable
fun RtpDualTrackPlayerScreen(
    title: String,
    playback: RtpDualTrackPlayback?,
    errorMessage: String?,
    unsupported: List<RtpUnsupportedStream>,
    playbackState: RtpPlayerState,
    positionMs: Long,
    muteState: RtpTrackMuteState,
    onBack: () -> Unit,
    onPlayPause: () -> Unit,
    onSeek: (Long) -> Unit,
    onTrackMuted: (left: Boolean, right: Boolean) -> Unit,
    onPacketClick: (Long) -> Unit,
    onRetry: () -> Unit,
    onCancel: () -> Unit
) {
    val context = LocalContext.current
    val scope = rememberCoroutineScope()
    val snackbarHostState = remember { SnackbarHostState() }
    var selectedSide by remember { mutableStateOf(RtpPlayerTrackSide.LEFT) }
    var dtmfExpanded by remember { mutableStateOf(false) }
    var pendingExport by remember { mutableStateOf<RtpDualTrackExport?>(null) }

    val exportComplete = stringResource(R.string.rtp_player_export_complete)
    val exportFailed = stringResource(R.string.rtp_player_export_failed)
    // 导出的是**已经解码好的**文件（`items` 的单声道或 `mix.wav`），这里只做一次复制，
    // 不再触发任何原生解码。
    val exportLauncher = rememberRtpWavExportLauncher { uri ->
        val pending = pendingExport
        pendingExport = null
        if (uri != null && pending != null) {
            scope.launch {
                val copied = withContext(Dispatchers.IO) {
                    runCatching {
                        rtpExportDestination(context, uri, pending.displayName)
                            .write(File(pending.filePath))
                    }.isSuccess
                }
                snackbarHostState.showSnackbar(if (copied) exportComplete else exportFailed)
            }
        }
    }

    var trackData by remember(playback) { mutableStateOf<RtpDualTrackRenderData?>(null) }
    LaunchedEffect(playback) {
        trackData = null
        val current = playback ?: return@LaunchedEffect
        trackData = withContext(Dispatchers.IO) {
            runCatching {
                RtpDualTrackRenderData(
                    left = current.left?.let(::readTrackRenderData),
                    right = current.right?.let(::readTrackRenderData)
                )
            }.getOrNull()
        }
    }

    BackHandler(onBack = onBack)

    Scaffold(
        topBar = {
            TopAppBar(
                title = {
                    Text(title, maxLines = 1, overflow = TextOverflow.Ellipsis)
                },
                navigationIcon = {
                    IconButton(onClick = onBack) {
                        Icon(
                            Icons.AutoMirrored.Filled.ArrowBack,
                            contentDescription = stringResource(R.string.back)
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
                .verticalScroll(rememberScrollState())
                .padding(horizontal = 16.dp, vertical = 12.dp)
        ) {
            Text(
                stringResource(R.string.rtp_dual_track_title),
                style = MaterialTheme.typography.titleMedium
            )
            Spacer(modifier = Modifier.height(4.dp))
            // 用 if/else 链而不是 when：只有 if/else 才会把「上一分支不成立」传给下一分支，
            // 从而把 playback 智能转换成非空。
            val currentPlayback = playback
            if (errorMessage != null) {
                DecodeMessage(
                    message = errorMessage,
                    actionLabel = stringResource(R.string.retry),
                    onAction = onRetry,
                    isError = true
                )
            } else if (currentPlayback == null) {
                DualTrackDecodeProgress(onCancel = onCancel)
            } else if (currentPlayback.left == null) {
                DecodeMessage(
                    message = stringResource(R.string.rtp_dual_track_no_audio),
                    actionLabel = stringResource(R.string.retry),
                    onAction = onRetry,
                    isError = true
                )
            } else {
                DualTrackContent(
                    playback = currentPlayback,
                    trackData = trackData,
                    playbackState = playbackState,
                    positionMs = positionMs,
                    muteState = muteState,
                    selectedSide = selectedSide,
                    onSideChange = { selectedSide = it },
                    onPlayPause = onPlayPause,
                    onSeek = onSeek,
                    onTrackMuted = onTrackMuted,
                    onPacketClick = onPacketClick,
                    dtmfExpanded = dtmfExpanded,
                    onToggleDtmf = { dtmfExpanded = !dtmfExpanded },
                    onExport = { export ->
                        pendingExport = export
                        exportLauncher.launch(export.displayName)
                    }
                )
            }

            if (unsupported.isNotEmpty()) {
                HorizontalDivider(modifier = Modifier.padding(vertical = 12.dp))
                Text(
                    stringResource(R.string.rtp_player_unsupported_title),
                    style = MaterialTheme.typography.titleMedium
                )
                unsupported.forEach { stream ->
                    Column(modifier = Modifier.padding(top = 8.dp)) {
                        Text(
                            stringResource(
                                R.string.rtp_player_unsupported_stream,
                                stream.streamId
                            ),
                            fontFamily = FontFamily.Monospace,
                            style = MaterialTheme.typography.bodyMedium
                        )
                        Text(
                            unsupportedReasonText(stream.reason),
                            style = MaterialTheme.typography.bodySmall,
                            color = MaterialTheme.colorScheme.onSurfaceVariant
                        )
                    }
                }
            }
        }
    }
}

/**
 * 双轨播放器的主体（解码成功之后）。
 *
 * 抽成单独的函数只为让 [RtpDualTrackPlayerScreen] 的 `when` 保持扁平；`remember` 与读盘状态
 * 都由调用方持有，这里全部是无状态计算。
 */
@OptIn(ExperimentalLayoutApi::class)
@Composable
private fun DualTrackContent(
    playback: RtpDualTrackPlayback,
    trackData: RtpDualTrackRenderData?,
    playbackState: RtpPlayerState,
    positionMs: Long,
    muteState: RtpTrackMuteState,
    selectedSide: RtpPlayerTrackSide,
    onSideChange: (RtpPlayerTrackSide) -> Unit,
    onPlayPause: () -> Unit,
    onSeek: (Long) -> Unit,
    onTrackMuted: (left: Boolean, right: Boolean) -> Unit,
    onPacketClick: (Long) -> Unit,
    dtmfExpanded: Boolean,
    onToggleDtmf: () -> Unit,
    onExport: (RtpDualTrackExport) -> Unit
) {
    val leftSource = playback.left
    val rightSource = playback.right
    val mix = playback.mix
    // 只有两轨齐备且原生层真的合成了立体声才算双轨；否则退化为 M2 的单声道呈现。
    val dual = playback.isDualTrack
    val durationMs = (mix?.durationMs ?: leftSource?.item?.durationMs ?: 0L).coerceAtLeast(0L)
    val mainSampleRate = trackData?.left?.sampleRate?.takeIf { it > 0 }
        ?: leftSource?.item?.sampleRate?.takeIf { it > 0 }
        ?: 0
    val leftAligned = leftSource?.let { source ->
        val data = trackData?.left
        rtpAlignTrackToSharedAxis(
            peaks = data?.peaks ?: ShortArray(0),
            samplesPerBucket = data?.samplesPerBucket ?: 1,
            sampleRate = data?.sampleRate ?: source.item.sampleRate,
            offsetMs = source.offsetMs,
            mainSampleRate = mainSampleRate
        )
    }
    val rightAligned = rightSource?.let { source ->
        val data = trackData?.right
        rtpAlignTrackToSharedAxis(
            peaks = data?.peaks ?: ShortArray(0),
            samplesPerBucket = data?.samplesPerBucket ?: 1,
            sampleRate = data?.sampleRate ?: source.item.sampleRate,
            offsetMs = source.offsetMs,
            mainSampleRate = mainSampleRate
        )
    }
    val gaps = buildList {
        leftSource?.let { addAll(rtpShiftGaps(it.item.gaps, it.offsetMs)) }
        rightSource?.let { addAll(rtpShiftGaps(it.item.gaps, it.offsetMs)) }
    }
    val events = buildList {
        leftSource?.let {
            addAll(rtpShiftEvents(it.item.events, it.offsetMs))
            addAll(rtpDtmfEvents(it.item.dtmf, it.offsetMs))
        }
        rightSource?.let {
            addAll(rtpShiftEvents(it.item.events, it.offsetMs))
            addAll(rtpDtmfEvents(it.item.dtmf, it.offsetMs))
        }
    }
    val dtmfEntries = remember(playback) {
        buildList {
            playback.left?.let { source ->
                source.item.dtmf.forEach {
                    add(sharedDtmf(it, source, RtpPlayerTrackSide.LEFT))
                }
            }
            playback.right?.let { source ->
                source.item.dtmf.forEach {
                    add(sharedDtmf(it, source, RtpPlayerTrackSide.RIGHT))
                }
            }
        }.sortedBy { it.atMs }
    }

    // 「跳到数据包」按当前选中轨道取帧映射：共享轴上的位置先换回该轨自身的时间。
    val frameSource = if (selectedSide == RtpPlayerTrackSide.RIGHT) rightSource else leftSource
    val frameData = if (selectedSide == RtpPlayerTrackSide.RIGHT) trackData?.right else trackData?.left
    val localMs = frameSource?.let { rtpTrackLocalMs(positionMs, it.offsetMs) }
    val currentFrame = if (frameData != null && localMs != null) {
        FrameMapFile.frameAt(localMs, frameData.frameMap)
    } else {
        null
    }

    val leftLabel = stringResource(R.string.rtp_dual_track_left)
    val rightLabel = stringResource(R.string.rtp_dual_track_right)

    TrackHeaderRow(
        label = leftLabel,
        identity = leftSource?.stream?.let { rtpStreamIdentity(it) },
        muted = muteState.left,
        showMute = dual,
        onMutedChange = { onTrackMuted(it, muteState.right) }
    )
    if (dual && rightSource != null) {
        TrackHeaderRow(
            label = rightLabel,
            identity = rtpStreamIdentity(rightSource.stream),
            muted = muteState.right,
            showMute = true,
            onMutedChange = { onTrackMuted(muteState.left, it) }
        )
    }

    Spacer(modifier = Modifier.height(4.dp))
    RtpWaveform(
        peaks = leftAligned?.peaks ?: ShortArray(0),
        sampleRate = mainSampleRate,
        samplesPerBucket = leftAligned?.samplesPerBucket ?: 1,
        durationMs = durationMs,
        gaps = gaps,
        events = events,
        playheadMs = positionMs.coerceIn(0L, durationMs),
        onSeek = onSeek,
        extraTracks = if (dual && rightAligned != null) {
            listOf(
                RtpWaveformTrack(
                    peaks = rightAligned.peaks,
                    samplesPerBucket = rightAligned.samplesPerBucket,
                    label = rightLabel
                )
            )
        } else {
            emptyList()
        },
        modifier = Modifier
            .fillMaxWidth()
            .height(if (dual) 208.dp else 144.dp)
    )

    // 时间轴下方的 DTMF 数字标签：与波形同一个 x 映射，点一下就把播放头送过去。
    if (dtmfEntries.isNotEmpty()) {
        Spacer(modifier = Modifier.height(2.dp))
        DtmfTimelineLabels(
            entries = dtmfEntries,
            durationMs = durationMs,
            onJump = { entry ->
                // 事件只可能来自一条流：跳转时把「当前轨道」也切到它的归属轨道，
                // 后续「跳到数据包」才会用对帧映射。
                onSideChange(entry.side)
                onSeek(entry.atMs)
            }
        )
    }

    PlaybackControls(
        playbackState = playbackState,
        positionMs = positionMs,
        durationMs = durationMs,
        onPlayPause = onPlayPause
    )

    Row(
        modifier = Modifier
            .fillMaxWidth()
            .padding(top = 4.dp),
        verticalAlignment = Alignment.CenterVertically
    ) {
        if (dual) {
            FilterChip(
                selected = selectedSide == RtpPlayerTrackSide.LEFT,
                onClick = { onSideChange(RtpPlayerTrackSide.LEFT) },
                label = { Text(stringResource(R.string.rtp_dual_track_jump_left)) }
            )
            Spacer(modifier = Modifier.width(8.dp))
            FilterChip(
                selected = selectedSide == RtpPlayerTrackSide.RIGHT,
                onClick = { onSideChange(RtpPlayerTrackSide.RIGHT) },
                label = { Text(stringResource(R.string.rtp_dual_track_jump_right)) }
            )
            Spacer(modifier = Modifier.width(8.dp))
        }
        Text(
            text = currentFrame?.let { stringResource(R.string.rtp_player_current_frame, it) }
                ?: stringResource(R.string.rtp_player_frame_unavailable),
            modifier = Modifier.weight(1f),
            style = MaterialTheme.typography.bodyMedium,
            maxLines = 1,
            overflow = TextOverflow.Ellipsis
        )
        TextButton(
            enabled = currentFrame != null,
            onClick = { currentFrame?.let(onPacketClick) }
        ) {
            Text(stringResource(R.string.rtp_player_jump_to_packet))
        }
    }

    // 原生层为了对齐两路采样率做了线性插值升采样——与 Wireshark 的差异点，必须说清楚，
    // 不能让它看起来像「和 Wireshark 完全一致」。
    if (mix?.resampled == true) {
        Text(
            stringResource(R.string.rtp_dual_track_resampled),
            modifier = Modifier.padding(top = 6.dp),
            style = MaterialTheme.typography.bodySmall,
            color = MaterialTheme.colorScheme.tertiary
        )
    }
    if (!dual) {
        Text(
            stringResource(R.string.rtp_dual_track_mono_note),
            modifier = Modifier.padding(top = 6.dp),
            style = MaterialTheme.typography.bodySmall,
            color = MaterialTheme.colorScheme.onSurfaceVariant
        )
    }

    HorizontalDivider(modifier = Modifier.padding(vertical = 8.dp))
    DtmfSection(
        entries = dtmfEntries,
        expanded = dtmfExpanded,
        onToggle = onToggleDtmf,
        onJump = { entry ->
            onSideChange(entry.side)
            onSeek(entry.atMs)
        }
    )

    HorizontalDivider(modifier = Modifier.padding(vertical = 8.dp))
    Text(
        stringResource(R.string.rtp_dual_track_export_title),
        style = MaterialTheme.typography.titleMedium
    )
    FlowRow(
        modifier = Modifier.padding(top = 4.dp),
        horizontalArrangement = Arrangement.spacedBy(8.dp),
        verticalArrangement = Arrangement.spacedBy(4.dp)
    ) {
        if (dual && leftSource != null && rightSource != null) {
            OutlinedButton(
                onClick = {
                    onExport(
                        RtpDualTrackExport(
                            filePath = leftSource.item.wavPath,
                            displayName = rtpWavFileName(leftSource.stream)
                        )
                    )
                }
            ) { Text(stringResource(R.string.rtp_dual_track_export_left)) }
            OutlinedButton(
                onClick = {
                    onExport(
                        RtpDualTrackExport(
                            filePath = rightSource.item.wavPath,
                            displayName = rtpWavFileName(rightSource.stream)
                        )
                    )
                }
            ) { Text(stringResource(R.string.rtp_dual_track_export_right)) }
        }
        val stereoPath = mix?.wavPath?.takeIf(String::isNotBlank)
        if (dual && leftSource != null && stereoPath != null) {
            OutlinedButton(
                onClick = {
                    onExport(
                        RtpDualTrackExport(
                            filePath = stereoPath,
                            displayName = rtpStereoExportFileName(leftSource.stream)
                        )
                    )
                }
            ) { Text(stringResource(R.string.rtp_dual_track_export_mix)) }
        } else if (leftSource != null) {
            OutlinedButton(
                onClick = {
                    onExport(
                        RtpDualTrackExport(
                            filePath = leftSource.item.wavPath,
                            displayName = rtpWavFileName(leftSource.stream)
                        )
                    )
                }
            ) { Text(stringResource(R.string.rtp_dual_track_export_mono)) }
        }
    }

    HorizontalDivider(modifier = Modifier.padding(vertical = 8.dp))
    Text(
        stringResource(R.string.rtp_player_info_title),
        style = MaterialTheme.typography.titleMedium
    )
    val trackInfos = listOfNotNull(
        leftSource?.let { it to leftLabel },
        if (dual) rightSource?.let { it to rightLabel } else null
    )
    trackInfos.forEach { (source, label) ->
        Text(
            "$label · ${source.item.codec} · ${source.item.sampleRate} Hz",
            modifier = Modifier.padding(top = 6.dp),
            style = MaterialTheme.typography.bodyMedium
        )
        InfoRow(stringResource(R.string.rtp_dual_track_offset), "${source.offsetMs} ms")
        InfoRow(stringResource(R.string.rtp_player_lost), source.item.stats.lost.toString())
        InfoRow(
            stringResource(R.string.rtp_player_truncated),
            source.item.stats.truncatedPackets.toString()
        )
    }
}

/** 单条轨道的表头：名称、流标识与静音开关。 */
@Composable
private fun TrackHeaderRow(
    label: String,
    identity: String?,
    muted: Boolean,
    showMute: Boolean,
    onMutedChange: (Boolean) -> Unit
) {
    Row(
        modifier = Modifier
            .fillMaxWidth()
            .padding(top = 4.dp),
        verticalAlignment = Alignment.CenterVertically
    ) {
        Column(modifier = Modifier.weight(1f)) {
            Text(label, style = MaterialTheme.typography.titleSmall)
            if (identity != null) {
                Text(
                    identity,
                    fontFamily = FontFamily.Monospace,
                    style = MaterialTheme.typography.bodySmall,
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                    maxLines = 1,
                    overflow = TextOverflow.Ellipsis
                )
            }
        }
        if (showMute) {
            Text(
                stringResource(R.string.rtp_dual_track_mute),
                style = MaterialTheme.typography.bodySmall,
                color = MaterialTheme.colorScheme.onSurfaceVariant
            )
            Spacer(modifier = Modifier.width(4.dp))
            Switch(checked = muted, onCheckedChange = onMutedChange)
        }
    }
}

/**
 * 时间轴下方的 DTMF 数字标签。
 *
 * 用 [BoxWithConstraints] 拿到宽度后按「事件时间 / 总时长」定位，与 [RtpWaveform] 里
 * `timeToX` 的口径一致；标签固定宽度并夹在左右边界内，最后一个数字不会跑出屏幕。
 */
@Composable
private fun DtmfTimelineLabels(
    entries: List<RtpSharedDtmf>,
    durationMs: Long,
    onJump: (RtpSharedDtmf) -> Unit
) {
    if (entries.isEmpty() || durationMs <= 0L) return
    val density = LocalDensity.current
    BoxWithConstraints(
        modifier = Modifier
            .fillMaxWidth()
            .height(RTP_DTMF_LABEL_HEIGHT)
    ) {
        val widthPx = with(density) { maxWidth.toPx() }
        val chipPx = with(density) { RTP_DTMF_CHIP_WIDTH.toPx() }
        val maxOffset = (widthPx - chipPx).coerceAtLeast(0f)
        entries.forEach { entry ->
            val fraction = entry.atMs.coerceIn(0L, durationMs).toDouble() / durationMs.toDouble()
            val offset = (fraction * widthPx - chipPx / 2f).toFloat().coerceIn(0f, maxOffset)
            Surface(
                shape = RoundedCornerShape(4.dp),
                color = MaterialTheme.colorScheme.secondaryContainer,
                contentColor = MaterialTheme.colorScheme.onSecondaryContainer,
                modifier = Modifier
                    .offset { IntOffset(offset.roundToInt(), 0) }
                    .width(RTP_DTMF_CHIP_WIDTH)
                    .clickable { onJump(entry) }
            ) {
                Text(
                    text = entry.digit,
                    modifier = Modifier.padding(vertical = 1.dp),
                    textAlign = TextAlign.Center,
                    style = MaterialTheme.typography.labelMedium,
                    maxLines = 1
                )
            }
        }
    }
}

/** 可折叠的 DTMF 列表：数字、开始时间、时长、帧号与跳转。 */
@Composable
private fun DtmfSection(
    entries: List<RtpSharedDtmf>,
    expanded: Boolean,
    onToggle: () -> Unit,
    onJump: (RtpSharedDtmf) -> Unit
) {
    Row(
        modifier = Modifier
            .fillMaxWidth()
            .clickable(onClick = onToggle),
        verticalAlignment = Alignment.CenterVertically
    ) {
        Text(
            text = stringResource(R.string.rtp_dual_track_dtmf_title, entries.size),
            modifier = Modifier.weight(1f),
            style = MaterialTheme.typography.titleMedium
        )
        Icon(
            imageVector = if (expanded) Icons.Default.ExpandLess else Icons.Default.ExpandMore,
            contentDescription = stringResource(
                if (expanded) R.string.rtp_dual_track_dtmf_collapse
                else R.string.rtp_dual_track_dtmf_expand
            )
        )
    }
    if (!expanded) return

    if (entries.isEmpty()) {
        Text(
            stringResource(R.string.rtp_dual_track_dtmf_empty),
            modifier = Modifier.padding(top = 6.dp),
            style = MaterialTheme.typography.bodyMedium,
            color = MaterialTheme.colorScheme.onSurfaceVariant
        )
        return
    }

    Row(modifier = Modifier.padding(top = 8.dp)) {
        DtmfCell(stringResource(R.string.rtp_dual_track_dtmf_digit), RTP_DTMF_DIGIT_WEIGHT)
        DtmfCell(stringResource(R.string.rtp_dual_track_dtmf_start), RTP_DTMF_TIME_WEIGHT)
        DtmfCell(stringResource(R.string.rtp_dual_track_dtmf_duration), RTP_DTMF_TIME_WEIGHT)
        DtmfCell(stringResource(R.string.rtp_dual_track_dtmf_frame), RTP_DTMF_FRAME_WEIGHT)
    }
    entries.forEach { entry ->
        Row(
            modifier = Modifier
                .fillMaxWidth()
                .padding(top = 2.dp),
            verticalAlignment = Alignment.CenterVertically
        ) {
            DtmfCell(entry.digit, RTP_DTMF_DIGIT_WEIGHT, monospace = true)
            DtmfCell(formatRtpPlayerTime(entry.atMs), RTP_DTMF_TIME_WEIGHT, monospace = true)
            DtmfCell(
                stringResource(R.string.rtp_dual_track_dtmf_ms, entry.durMs),
                RTP_DTMF_TIME_WEIGHT,
                monospace = true
            )
            DtmfCell(
                stringResource(R.string.rtp_dual_track_frame_number, entry.frame),
                RTP_DTMF_FRAME_WEIGHT,
                monospace = true
            )
            TextButton(onClick = { onJump(entry) }) {
                Text(stringResource(R.string.rtp_dual_track_dtmf_jump))
            }
        }
    }
}

@Composable
private fun RowScope.DtmfCell(
    text: String,
    weight: Float,
    monospace: Boolean = false
) {
    Text(
        text = text,
        modifier = Modifier.weight(weight),
        style = MaterialTheme.typography.bodySmall,
        fontFamily = if (monospace) FontFamily.Monospace else null,
        maxLines = 1,
        overflow = TextOverflow.Ellipsis
    )
}

/** 解码中的进度：没有逐帧进度可用，就只给一个诚实的「正在解码 + 取消」。 */
@Composable
private fun DualTrackDecodeProgress(onCancel: () -> Unit) {
    Column(modifier = Modifier.padding(top = 16.dp)) {
        Text(
            stringResource(R.string.rtp_dual_track_decoding),
            style = MaterialTheme.typography.bodyMedium
        )
        LinearProgressIndicator(
            modifier = Modifier
                .fillMaxWidth()
                .padding(top = 8.dp)
        )
        Button(
            onClick = onCancel,
            modifier = Modifier.padding(top = 12.dp)
        ) {
            Text(stringResource(R.string.cancel))
        }
    }
}

/** 读一条轨道的 peaks 与帧映射；由调用方放在 IO 线程并包 `runCatching`。 */
private fun readTrackRenderData(source: RtpPlayerTrackSource): RtpTrackRenderData {
    val (header, peaks) = PeaksFile.read(File(source.item.peaksPath))
    return RtpTrackRenderData(
        peaks = peaks,
        samplesPerBucket = header.samplesPerBucket,
        sampleRate = header.sampleRate,
        frameMap = FrameMapFile.read(File(source.item.mapPath))
    )
}

@Composable
private fun rtpStreamIdentity(stream: RtpStream): String = stringResource(
    R.string.rtp_player_stream_identity,
    stream.src,
    stream.srcPort,
    stream.dst,
    stream.dstPort
)

/** 立体声导出名：在左声道名后加 `_stereo`，一眼能看出它由哪条呼叫混出来。 */
private fun rtpStereoExportFileName(left: RtpStream): String =
    rtpWavFileName(left).removeSuffix(RTP_WAV_SUFFIX) + RTP_STEREO_SUFFIX + RTP_WAV_SUFFIX

private fun sharedDtmf(
    event: RtpDtmfEvent,
    source: RtpPlayerTrackSource,
    side: RtpPlayerTrackSide
): RtpSharedDtmf = RtpSharedDtmf(
    digit = event.digit,
    atMs = rtpSharedAxisMs(event.atMs, source.offsetMs),
    durMs = event.durMs,
    frame = event.frame,
    side = side
)

private data class RtpWaveformData(
    val header: PeaksFile.Header,
    val peaks: ShortArray,
    val frameMap: List<FrameMapFile.Entry>
)

/** 双轨模式下一侧前置静音桶数的上限：异常偏移不该被换算成一次巨大的分配。 */
private const val RTP_MAX_SHIFT_BUCKETS = 500_000

/** DTMF 标记用的 `RtpEvent.type`，`value` 是数字本身。 */
private const val RTP_DTMF_EVENT_TYPE = "dtmf"

private val RTP_DTMF_CHIP_WIDTH = 26.dp
private val RTP_DTMF_LABEL_HEIGHT = 20.dp
private const val RTP_DTMF_DIGIT_WEIGHT = 0.14f
private const val RTP_DTMF_TIME_WEIGHT = 0.26f
private const val RTP_DTMF_FRAME_WEIGHT = 0.2f

private const val RTP_WAV_SUFFIX = ".wav"
private const val RTP_STEREO_SUFFIX = "_stereo"
