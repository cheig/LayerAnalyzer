// Copyright (c) 2026 cheig
// LayerAnalyzer - https://github.com/cheig/LayerAnalyzer
// Licensed under GNU GPL version 3; see LICENSE.

package com.example.layanalyzer.ui.components.rtp

import android.content.Context
import android.graphics.SurfaceTexture
import android.view.Surface
import android.view.TextureView
import androidx.activity.compose.BackHandler
import androidx.compose.foundation.Canvas
import androidx.compose.foundation.background
import androidx.compose.foundation.gestures.detectHorizontalDragGestures
import androidx.compose.foundation.gestures.detectTapGestures
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.aspectRatio
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.verticalScroll
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.automirrored.filled.ArrowBack
import androidx.compose.material.icons.filled.Pause
import androidx.compose.material.icons.filled.PlayArrow
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.HorizontalDivider
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.LinearProgressIndicator
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Scaffold
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.material3.TopAppBar
import androidx.compose.runtime.Composable
import androidx.compose.runtime.DisposableEffect
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.rememberUpdatedState
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.geometry.Offset
import androidx.compose.ui.geometry.Size
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.input.pointer.pointerInput
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.dp
import androidx.compose.ui.viewinterop.AndroidView
import com.example.layanalyzer.R
import com.example.layanalyzer.media.RtpPlayerState
import com.example.layanalyzer.viewmodel.RtpVideoPreviewUiState
import kotlin.math.roundToLong

/**
 * RTP5-KT-03：应用内预览页，[RtpPlayerScreen] 的视频兄弟。
 *
 * 无状态：播放状态、位置、时长、`.vidx` 读出来的访问单元全部由宿主（`RtpViewModel`）给，
 * 本页只做三件事 —— 把 `TextureView` 的 Surface 交出去、画进度条（含损坏帧标红）、把
 * 「当前帧对应的数据包号」显示出来并让宿主跳过去。
 *
 * **`TextureView` 与重组的坑**（这是本文件唯一真正需要小心的地方）：
 *  - `AndroidView` 的 `factory` 只在第一次组合时跑，闭包里捕获的回调是**那一刻**的。回调
 *    通过 `rememberUpdatedState` 读，重组之后 `TextureView` 调到的仍然是宿主最新的那一份，
 *    不会留着一个过期的 lambda。
 *  - Surface 的生死有自己的节奏，与重组无关：`onSurfaceTextureAvailable` 可能在宿主
 *    `load` 之前到（这时控制器先存着 Surface），也可能在播着的时候到（控制器直接换上去）。
 *    `onSurfaceTextureDestroyed` 里**先**通知宿主放手（宿主会暂停播放器），再释放我们包的
 *    那层 `Surface`，最后返回 true 让框架去释放 `SurfaceTexture` 本身 —— 顺序反了会让
 *    播放器短暂持有一个已释放的 Surface。
 *  - 离开组合时再补一次 `onDetachSurface`：`TextureView` 从窗口上摘下来时
 *    `onSurfaceTextureDestroyed` 通常会被调用，但「通常」不是契约，而控制器上的 detachment
 *    是幂等的（重复调用只是再暂停一次已经暂停的播放器）。
 *
 * @param state 打开的 MP4 与它的 `.vidx`
 * @param onJumpToPacket 把当前数据包号交回宿主（跳去数据包列表）
 * @param onAttachSurface / @param onDetachSurface 交给宿主的播放器；Surface 由本页创建与释放
 */
@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun RtpVideoPreviewScreen(
    state: RtpVideoPreviewUiState,
    playbackState: RtpPlayerState,
    positionMs: Long,
    durationMs: Long,
    onBack: () -> Unit,
    onPlayPause: () -> Unit,
    onSeek: (Long) -> Unit,
    onJumpToPacket: (Long) -> Unit,
    onAttachSurface: (Surface) -> Unit,
    onDetachSurface: () -> Unit
) {
    BackHandler(onBack = onBack)

    val safeDurationMs = durationMs.coerceAtLeast(0L)
    val safePositionMs = if (safeDurationMs > 0L) {
        positionMs.coerceIn(0L, safeDurationMs)
    } else {
        positionMs.coerceAtLeast(0L)
    }
    val spans = remember(state.accessUnits, safeDurationMs) {
        rtpPreviewCorruptSpans(state.accessUnits, safeDurationMs * MICROS_PER_MILLI)
    }
    val accessUnit = remember(state.accessUnits, safePositionMs) {
        rtpPreviewAccessUnitAt(
            positionUs = safePositionMs * MICROS_PER_MILLI,
            entries = state.accessUnits
        )
    }
    val currentFrame = accessUnit?.entry?.firstFrame?.toLong()

    Scaffold(
        topBar = {
            TopAppBar(
                title = {
                    Text(
                        text = stringResource(R.string.rtp_video_preview_title),
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
                }
            )
        }
    ) { padding ->
        Column(
            modifier = Modifier
                .padding(padding)
                .fillMaxSize()
                .verticalScroll(rememberScrollState())
                .padding(horizontal = 16.dp, vertical = 12.dp)
        ) {
            if (!state.isOpen) {
                // 宿主只在能预览时打开这一页；真被打开而没有文件时说明白是哪一种，
                // 不留一块空白（README §4.5.4）。
                Text(
                    text = state.errorMessage
                        ?: stringResource(R.string.rtp_video_preview_missing),
                    color = MaterialTheme.colorScheme.error
                )
                return@Column
            }

            RtpPreviewSurface(
                onAttachSurface = onAttachSurface,
                onDetachSurface = onDetachSurface,
                modifier = Modifier
                    .fillMaxWidth()
                    .aspectRatio(RTP_PREVIEW_ASPECT_RATIO)
                    // 视频视口的底色就是黑的（信箱边），深浅色主题下都成立，所以它是
                    // 本文件里唯一一个固定颜色。
                    .background(Color.Black)
            )

            when (playbackState) {
                RtpPlayerState.Preparing,
                RtpPlayerState.Idle -> {
                    LinearProgressIndicator(
                        modifier = Modifier
                            .fillMaxWidth()
                            .padding(top = 8.dp)
                    )
                    Text(
                        stringResource(R.string.rtp_video_preview_preparing),
                        modifier = Modifier.padding(top = 4.dp),
                        style = MaterialTheme.typography.bodySmall,
                        color = MaterialTheme.colorScheme.onSurfaceVariant
                    )
                }

                is RtpPlayerState.Error -> Text(
                    text = playbackState.message
                        .ifBlank { stringResource(R.string.rtp_video_preview_failed) },
                    modifier = Modifier.padding(top = 8.dp),
                    color = MaterialTheme.colorScheme.error
                )

                RtpPlayerState.Playing,
                RtpPlayerState.Paused,
                RtpPlayerState.Completed -> Unit
            }

            RtpPreviewProgressBar(
                positionMs = safePositionMs,
                durationMs = safeDurationMs,
                spans = spans,
                onSeek = onSeek,
                modifier = Modifier
                    .fillMaxWidth()
                    .height(RTP_PREVIEW_BAR_HEIGHT)
                    .padding(top = 12.dp)
            )

            PreviewControls(
                playbackState = playbackState,
                positionMs = safePositionMs,
                durationMs = safeDurationMs,
                onPlayPause = onPlayPause
            )

            Text(
                text = stringResource(
                    R.string.rtp_video_preview_corrupt_count,
                    state.corruptFrameCount
                ),
                modifier = Modifier.padding(top = 8.dp),
                style = MaterialTheme.typography.bodySmall,
                color = if (state.corruptFrameCount > 0) MaterialTheme.colorScheme.error
                else MaterialTheme.colorScheme.onSurfaceVariant
            )

            // 索引读不出来时视频照放，但必须说清楚少了什么：这几行字是唯一的说明。
            state.indexError?.let { message ->
                Text(
                    text = stringResource(R.string.rtp_video_preview_no_index, message),
                    modifier = Modifier.padding(top = 4.dp),
                    style = MaterialTheme.typography.bodySmall,
                    color = MaterialTheme.colorScheme.onSurfaceVariant
                )
            }

            HorizontalDivider(modifier = Modifier.padding(vertical = 8.dp))

            Row(
                modifier = Modifier.fillMaxWidth(),
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
                    onClick = { currentFrame?.let(onJumpToPacket) }
                ) {
                    Text(stringResource(R.string.rtp_player_jump_to_packet))
                }
            }
        }
    }
}

/**
 * 承载视频的 `TextureView`。
 *
 * 三处与「重组」有关的刻意安排：回调经 [rememberUpdatedState] 读取（`factory` 只跑一次，
 * 捕获的 lambda 会过期）；`onSurfaceTextureDestroyed` 里先让宿主放手再释放 Surface；
 * 离开组合时用 [DisposableEffect] 再通知一次（幂等）。
 */
@Composable
private fun RtpPreviewSurface(
    onAttachSurface: (Surface) -> Unit,
    onDetachSurface: () -> Unit,
    modifier: Modifier = Modifier
) {
    val currentAttach by rememberUpdatedState(onAttachSurface)
    val currentDetach by rememberUpdatedState(onDetachSurface)

    AndroidView(
        factory = { viewContext ->
            RtpPreviewTextureView(
                context = viewContext,
                onSurfaceAvailable = { surface -> currentAttach(surface) },
                onSurfaceReleased = { currentDetach() }
            )
        },
        modifier = modifier
    )

    DisposableEffect(Unit) {
        onDispose { currentDetach() }
    }
}

/**
 * `TextureView` 的子类：自己实现 `SurfaceTextureListener`，把「Surface 什么时候来、什么时候
 * 走」翻译成两个回调。
 *
 * 它持有自己包出来的那个 [Surface]，因为**释放是它的责任**：框架只管 `SurfaceTexture`，
 * 包在外面的 `Surface` 是这里建的。
 */
private class RtpPreviewTextureView(
    context: Context,
    private val onSurfaceAvailable: (Surface) -> Unit,
    private val onSurfaceReleased: () -> Unit
) : TextureView(context), TextureView.SurfaceTextureListener {

    private var surface: Surface? = null

    init {
        surfaceTextureListener = this
    }

    override fun onSurfaceTextureAvailable(texture: SurfaceTexture, width: Int, height: Int) {
        val created = Surface(texture)
        surface = created
        onSurfaceAvailable(created)
    }

    override fun onSurfaceTextureSizeChanged(
        texture: SurfaceTexture,
        width: Int,
        height: Int
    ) = Unit

    override fun onSurfaceTextureUpdated(texture: SurfaceTexture) = Unit

    override fun onSurfaceTextureDestroyed(texture: SurfaceTexture): Boolean {
        // 顺序是有意的：先让播放器放开它（宿主会顺带暂停），再释放这一层。
        onSurfaceReleased()
        surface?.let { runCatching { it.release() } }
        surface = null
        // true：SurfaceTexture 交给框架释放，这里只包了一层 Surface。
        return true
    }
}

/** 播放/暂停与 `mm:ss.S / mm:ss.S`，与音频播放器同一种排版。 */
@Composable
private fun PreviewControls(
    playbackState: RtpPlayerState,
    positionMs: Long,
    durationMs: Long,
    onPlayPause: () -> Unit
) {
    val isPlaying = playbackState == RtpPlayerState.Playing
    Row(
        modifier = Modifier
            .fillMaxWidth()
            .padding(top = 4.dp),
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
}

/**
 * 进度条：底层轨道、损坏区间（红）、已播放部分、播放头。点一下或横向拖动都能跳。
 *
 * 与 [RtpWaveform] 同一套手势口径：拖动过程中只动本地的播放头（`displayedPlayheadMs`），
 * 松手才把目标位置交给宿主，宿主那边再决定什么时候真的下发给播放器。
 *
 * 损坏区间按**比例**画；宽度为 0 的区间（时间轴末端不足一像素的那种）给一个最小宽度，
 * 否则「有损坏」和「没损坏」画出来一模一样。
 */
@Composable
private fun RtpPreviewProgressBar(
    positionMs: Long,
    durationMs: Long,
    spans: List<RtpVideoPreviewSpan>,
    onSeek: (Long) -> Unit,
    modifier: Modifier = Modifier
) {
    val colorScheme = MaterialTheme.colorScheme
    val trackColor = colorScheme.surfaceVariant
    val playedColor = colorScheme.primary
    val corruptColor = colorScheme.error
    val playheadColor = colorScheme.onSurface

    var isDragging by remember { mutableStateOf(false) }
    var displayedPlayheadMs by remember { mutableStateOf(positionMs.coerceIn(0L, durationMs)) }
    val currentOnSeek by rememberUpdatedState(onSeek)

    LaunchedEffect(positionMs, durationMs, isDragging) {
        if (!isDragging) {
            displayedPlayheadMs = positionMs.coerceIn(0L, durationMs)
        }
    }

    Canvas(
        modifier = modifier
            .pointerInput(durationMs) {
                detectTapGestures { position ->
                    if (size.width <= 0 || durationMs <= 0L) return@detectTapGestures
                    val seekMs = rtpPreviewSeekMsAt(position.x, size.width, durationMs)
                    displayedPlayheadMs = seekMs
                    currentOnSeek(seekMs)
                }
            }
            .pointerInput(durationMs) {
                detectHorizontalDragGestures(
                    onDragStart = { position ->
                        if (size.width <= 0 || durationMs <= 0L) {
                            return@detectHorizontalDragGestures
                        }
                        isDragging = true
                        displayedPlayheadMs =
                            rtpPreviewSeekMsAt(position.x, size.width, durationMs)
                    },
                    onHorizontalDrag = { change, _ ->
                        if (size.width > 0 && durationMs > 0L) {
                            displayedPlayheadMs =
                                rtpPreviewSeekMsAt(change.position.x, size.width, durationMs)
                            change.consume()
                        }
                    },
                    onDragEnd = {
                        if (isDragging) {
                            isDragging = false
                            currentOnSeek(displayedPlayheadMs)
                        }
                    },
                    onDragCancel = { isDragging = false }
                )
            }
    ) {
        if (size.width <= 0f || size.height <= 0f) return@Canvas
        val width = size.width
        val barHeight = minOf(RTP_PREVIEW_BAR_STROKE.toPx(), size.height)
        val top = (size.height - barHeight) / 2f
        val minimumSpanWidth = RTP_PREVIEW_MIN_SPAN.toPx()

        drawRect(
            color = trackColor,
            topLeft = Offset(0f, top),
            size = Size(width, barHeight)
        )
        spans.forEach { span ->
            val left = span.startFraction.coerceIn(0f, 1f) * width
            val right = span.endFraction.coerceIn(0f, 1f) * width
            drawRect(
                color = corruptColor,
                topLeft = Offset(left, top),
                size = Size((right - left).coerceAtLeast(minimumSpanWidth), barHeight)
            )
        }
        val playedFraction = if (durationMs > 0L) {
            displayedPlayheadMs.coerceIn(0L, durationMs).toFloat() / durationMs.toFloat()
        } else {
            0f
        }
        drawRect(
            color = playedColor,
            topLeft = Offset(0f, top),
            size = Size(width * playedFraction.coerceIn(0f, 1f), barHeight)
        )
        drawLine(
            color = playheadColor,
            start = Offset(width * playedFraction.coerceIn(0f, 1f), 0f),
            end = Offset(width * playedFraction.coerceIn(0f, 1f), size.height),
            strokeWidth = 2f
        )
    }
}

/** 进度条上一点对应的位置；容器宽度或时长不可用时回 0。 */
private fun rtpPreviewSeekMsAt(x: Float, width: Int, durationMs: Long): Long {
    if (width <= 0 || durationMs <= 0L) return 0L
    val fraction = x.coerceIn(0f, width.toFloat()) / width.toFloat()
    return (fraction * durationMs.toDouble()).roundToLong().coerceIn(0L, durationMs)
}

/** `MediaPlayer` 的位置是毫秒，`.vidx` 的时间是微秒。 */
private const val MICROS_PER_MILLI = 1_000L

/** 视频视口的宽高比：KT-01 的封装器在宽高读不出来时用 1280x720，这里与它一致。 */
private const val RTP_PREVIEW_ASPECT_RATIO = 16f / 9f

private val RTP_PREVIEW_BAR_HEIGHT = 48.dp
private val RTP_PREVIEW_BAR_STROKE = 8.dp

/** 损坏区间的最小可见宽度：不足一像素的区间也要看得见。 */
private val RTP_PREVIEW_MIN_SPAN = 2.dp
