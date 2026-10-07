// Copyright (c) 2026 cheig
// LayerAnalyzer - https://github.com/cheig/LayerAnalyzer
// Licensed under GNU GPL version 3; see LICENSE.

package com.example.layanalyzer.ui.components.rtp

import android.net.Uri
import androidx.activity.compose.ManagedActivityResultLauncher
import androidx.activity.compose.rememberLauncherForActivityResult
import androidx.activity.result.contract.ActivityResultContracts
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.widthIn
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.verticalScroll
import androidx.compose.material3.AlertDialog
import androidx.compose.material3.Button
import androidx.compose.material3.Checkbox
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.dp
import com.example.layanalyzer.R
import com.example.layanalyzer.media.VideoMuxFormat
import com.example.layanalyzer.model.RtpStream
import com.example.layanalyzer.model.RtpVideoExportFormat
import com.example.layanalyzer.model.RtpVideoExportResult
import com.example.layanalyzer.model.rtpVideoFileName
import com.example.layanalyzer.model.rtpVideoRawMimeType
import com.example.layanalyzer.viewmodel.RtpVideoExportSummary

/**
 * RTP5-UI-01：视频导出的两个对话框与 SAF 目的地接线。
 *
 * 与 `RtpExportActions.kt`（音频那一套）刻意分开，理由和 `RtpVideoExportFormat` 不在
 * `RtpExportFormat` 里一样：视频的**格式表**、**MIME**、**选项**都不是音频那张表的一项，
 * 硬塞进去只会让两边都开始处理「这个取值对这条流不适用」。
 *
 * 这里的一个 `android.*` 类型（[Uri]）只在 [rememberRtpVideoExportLauncher] 的参数里出现，
 * 纯决策在 `RtpVideoPresentation.kt`，所以文件名的后缀、能不能导出、摘要上那几个数字都还有
 * JVM 单测。
 */

/**
 * 一次成功 MP4 导出留下的那份可预览产物。
 *
 * 它是**宿主**（`PacketListScreen`）记的账，不是 ViewModel 的状态：`RtpViewModel` 的
 * `videoPreviewAvailability` 回答的是「这两个文件 + 这台设备能不能播」，但 `Ready` 里没有
 * 流 id（那是 KT-03 冻结的形状），所以「这份 MP4 属于哪条流」只能由发起导出的那一层记。
 * 两份状态取交集才让菜单项出现：见 `RtpStreamsScreen` 的 `previewStreamIds`。
 */
data class RtpVideoPreviewTarget(val mp4Path: String, val indexPath: String)

/**
 * CreateDocument 用的 MIME：MP4 是 [VideoMuxFormat.MIME_MP4]，裸流由编码决定
 * （`video/h264` / `video/hevc`）；拿不出具体 MIME 时 null（调用方 fail-closed，不猜）。
 *
 * MP4 与裸流各走各的，所以这里和 `RtpViewModel.videoOpenMimeTypes` 不是同一件事：那个是
 * 「交给外部应用**打开**」的候选顺序（裸流多一个 `application/octet-stream` 回退），
 * 这里是「让用户**存**一个文件」——存文件时挑 MIME 只看内容，没有回退可言。
 */
fun rtpVideoExportMimeType(codec: String, format: RtpVideoExportFormat): String? = when (format) {
    RtpVideoExportFormat.MP4 -> VideoMuxFormat.MIME_MP4
    RtpVideoExportFormat.RAW -> rtpVideoRawMimeType(codec)
}

/**
 * 视频产物的 CreateDocument launcher（`Uri?` 为 null 表示用户取消）。
 *
 * `CreateDocument` 的 MIME 在构造时就固定，而 `rememberLauncherForActivityResult` 只在第一次
 * 组合时取一次 contract，所以调用方必须**无条件**地按需要的 MIME 各建一个
 * （`video/mp4`、`video/h264`、`video/hevc`），不能按当前流算一个 MIME 传进来 —— 那样第一条
 * 流的 MIME 会一直用到会话结束。这与 `rememberRtpFormatExportLauncher` 是同一个约定。
 */
@Composable
fun rememberRtpVideoExportLauncher(
    mimeType: String,
    onResult: (Uri?) -> Unit
): ManagedActivityResultLauncher<String, Uri?> =
    rememberLauncherForActivityResult(
        ActivityResultContracts.CreateDocument(mimeType),
        onResult
    )

/**
 * 视频导出选项对话框（RTP5-UI-01）。
 *
 * 产物由**菜单项**选定（卡片上「导出 MP4」与「导出裸流」是两个条目），本对话框只把两个选项
 * 收齐再确认 —— 所以它没有「选格式」这一步，也就不可能出现「选了格式才发现这条流导不出来」
 * 的空转。[format] 只用来显示这次要写的是什么（`.mp4` / `.h264`）。
 *
 * 两个选项是卡片写死的一对默认值：**从关键帧开始默认开**（否则开头几帧多半是花屏）、
 * **丢弃损坏帧默认关**（开了就与参考输出的字节不同，QA-01 的对比要的是关着的那一份）。
 * 两个选项对 MP4 与裸流都生效 —— 它们是 `exportRtpVideo` 请求里的两个字段，与产物格式无关。
 *
 * [hevcDecoderMissing] 为 true 时在按钮上方给一句提示，**但确认按钮照常可点**：卡片要的是
 * 「给提示，但仍然允许导出」。提示文案与 `RtpViewModel.hevcDecoderAvailability` 是同一句。
 */
@Composable
fun RtpVideoExportDialog(
    stream: RtpStream,
    format: RtpVideoExportFormat,
    hevcDecoderMissing: Boolean,
    onConfirm: (startAtKeyframe: Boolean, dropCorrupt: Boolean) -> Unit,
    onDismiss: () -> Unit
) {
    // 选项按「流 + 产物」重置：换一条流或换一种产物就是一次新的导出，不该继承上一次的勾选。
    var startAtKeyframe by remember(stream.id, format) { mutableStateOf(true) }
    var dropCorrupt by remember(stream.id, format) { mutableStateOf(false) }
    val fileName = remember(stream, format) { rtpVideoFileName(stream, format) }
    val unknown = stringResource(R.string.unknown)

    AlertDialog(
        onDismissRequest = onDismiss,
        title = {
            Text(
                stringResource(R.string.rtp_video_export_title),
                maxLines = 1,
                overflow = TextOverflow.Ellipsis
            )
        },
        text = {
            Column(
                modifier = Modifier
                    .widthIn(max = 560.dp)
                    .verticalScroll(rememberScrollState())
            ) {
                Text(
                    text = stream.codec.ifBlank { unknown },
                    style = MaterialTheme.typography.labelLarge,
                    maxLines = 1,
                    overflow = TextOverflow.Ellipsis
                )
                Text(
                    text = stringResource(
                        R.string.rtp_player_stream_identity,
                        stream.src,
                        stream.srcPort,
                        stream.dst,
                        stream.dstPort
                    ),
                    modifier = Modifier.padding(top = 2.dp),
                    style = MaterialTheme.typography.bodySmall,
                    fontFamily = FontFamily.Monospace,
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                    maxLines = 1,
                    overflow = TextOverflow.Ellipsis
                )
                if (fileName != null) {
                    Text(
                        text = fileName,
                        modifier = Modifier.padding(top = 2.dp),
                        style = MaterialTheme.typography.bodySmall,
                        color = MaterialTheme.colorScheme.onSurfaceVariant,
                        maxLines = 1,
                        overflow = TextOverflow.Ellipsis
                    )
                }

                VideoExportOption(
                    checked = startAtKeyframe,
                    onCheckedChange = { startAtKeyframe = it },
                    label = stringResource(R.string.rtp_video_export_start_at_keyframe)
                )
                VideoExportOption(
                    checked = dropCorrupt,
                    onCheckedChange = { dropCorrupt = it },
                    label = stringResource(R.string.rtp_video_export_drop_corrupt)
                )

                if (hevcDecoderMissing) {
                    Text(
                        text = stringResource(R.string.rtp_video_hevc_decoder_missing),
                        modifier = Modifier.padding(top = 8.dp),
                        style = MaterialTheme.typography.bodySmall,
                        color = MaterialTheme.colorScheme.tertiary
                    )
                }

                if (fileName == null) {
                    // 菜单里这种流（`PS`）的视频动作全是置灰的，所以这里是同一条判定的兜底：
                    // 宁可说明白，也不给一个按下去必然失败的按钮（README §4.5.4）。
                    Text(
                        text = stringResource(R.string.rtp_video_export_none),
                        modifier = Modifier.padding(top = 8.dp),
                        style = MaterialTheme.typography.bodySmall,
                        color = MaterialTheme.colorScheme.error
                    )
                }
            }
        },
        confirmButton = {
            Button(
                onClick = { onConfirm(startAtKeyframe, dropCorrupt) },
                enabled = fileName != null
            ) {
                Text(stringResource(R.string.rtp_video_export_action))
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
 * 导出结果摘要对话框（RTP5-UI-01）。
 *
 * 卡片要求的四个数字（分辨率、帧数、损坏帧数、不支持的包型计数）都来自这次导出的原生结果
 * [result]；它是 `null` 时（那条流没导出成功，`RtpVideoExportSummary.results` 里没有它）
 * 只列文件与失败原因，绝不现编数字。
 *
 * [canPreview] 由调用方决定（见 `RtpVideoPreviewTarget` 的说明），它同时要求「这次导出的是
 * MP4」「宿主账本里有这条流」和「KT-03 的可用性结论是 Ready」——三者缺一就不给这个按钮，
 * 因为卡片要的是**不显示**，而不是一个按下去没有用的灰按钮。
 *
 * 但「不显示」不该等于「不说」：入口真的缺在**编码**上时（这台设备没有该编码的解码器），
 * [previewNotice] 把 KT-03 那句话摆在这里。菜单里没地方说这件事（那里只有一行条目），
 * 而刚导出完 MP4 的这一刻正是用户会问「为什么不能预览」的时候 —— 与 KT-02 的
 * `rtp_video_hevc_decoder_missing` 是同一条口径：给提示，但什么都照做。
 */
@Composable
fun RtpVideoExportResultDialog(
    summary: RtpVideoExportSummary,
    result: RtpVideoExportResult?,
    canPreview: Boolean,
    previewNotice: String?,
    onPreview: () -> Unit,
    onDismiss: () -> Unit
) {
    val unknown = stringResource(R.string.unknown)
    AlertDialog(
        onDismissRequest = onDismiss,
        title = {
            Text(
                stringResource(R.string.rtp_video_export_result_title),
                maxLines = 1,
                overflow = TextOverflow.Ellipsis
            )
        },
        text = {
            Column(
                modifier = Modifier
                    .widthIn(max = 560.dp)
                    .verticalScroll(rememberScrollState())
            ) {
                if (result != null) {
                    VideoSummaryRow(
                        label = stringResource(R.string.rtp_player_codec),
                        value = listOf(result.codec, result.profile, result.level)
                            .filter(String::isNotBlank)
                            .joinToString(separator = " ")
                            .ifBlank { unknown }
                    )
                    VideoSummaryRow(
                        label = stringResource(R.string.rtp_video_export_result_resolution),
                        // 宽高读不出来时显示「未知」：既不是 0×0，也不是封装器那个 1280×720
                        // 回退（见 `rtpVideoResolutionText`）。
                        value = rtpVideoResolutionText(result) ?: unknown
                    )
                    VideoSummaryRow(
                        label = stringResource(R.string.rtp_video_export_result_frames),
                        value = stringResource(
                            R.string.rtp_video_export_result_frames_value,
                            result.frames,
                            result.keyframes
                        )
                    )
                    VideoSummaryRow(
                        label = stringResource(R.string.rtp_video_export_result_corrupt),
                        value = result.corruptFrames.toString()
                    )
                    VideoSummaryRow(
                        label = stringResource(R.string.rtp_video_export_result_unsupported),
                        // 总数，数到了具体包型时再跟上括号里的明细；一个都没有时就是 `0`，
                        // 不挂一对空的括号。
                        value = rtpVideoUnsupportedNalSummary(result)
                    )
                }

                summary.files.forEach { file ->
                    VideoSummaryRow(
                        label = stringResource(R.string.rtp_video_export_result_file),
                        value = file.displayName
                    )
                }

                summary.failures.forEach { failure ->
                    Text(
                        text = failure.message.ifBlank {
                            stringResource(R.string.rtp_video_export_failed)
                        },
                        modifier = Modifier.padding(top = 8.dp),
                        style = MaterialTheme.typography.bodySmall,
                        color = MaterialTheme.colorScheme.error
                    )
                }

                if (previewNotice != null) {
                    Text(
                        text = previewNotice,
                        modifier = Modifier.padding(top = 8.dp),
                        style = MaterialTheme.typography.bodySmall,
                        color = MaterialTheme.colorScheme.tertiary
                    )
                }
            }
        },
        confirmButton = {
            if (canPreview) {
                Button(onClick = onPreview) {
                    Text(
                        stringResource(R.string.rtp_video_preview_action),
                        maxLines = 1,
                        overflow = TextOverflow.Ellipsis
                    )
                }
            }
        },
        dismissButton = {
            TextButton(onClick = onDismiss) {
                Text(stringResource(R.string.close))
            }
        }
    )
}

/** 一个勾选项：标签在右，复选框在左，整行可点。 */
@Composable
private fun VideoExportOption(
    checked: Boolean,
    onCheckedChange: (Boolean) -> Unit,
    label: String
) {
    Row(
        modifier = Modifier
            .fillMaxWidth()
            .padding(top = 8.dp),
        verticalAlignment = Alignment.CenterVertically
    ) {
        Checkbox(checked = checked, onCheckedChange = onCheckedChange)
        Text(
            text = label,
            modifier = Modifier.padding(start = 4.dp),
            style = MaterialTheme.typography.bodyMedium,
            maxLines = 2,
            overflow = TextOverflow.Ellipsis
        )
    }
}

/** 摘要里的一行：左边是标签，右边是值（值可以换行，长它不截断）。 */
@Composable
private fun VideoSummaryRow(label: String, value: String) {
    Row(modifier = Modifier.fillMaxWidth().padding(top = 6.dp)) {
        Text(
            text = label,
            modifier = Modifier.weight(1f),
            style = MaterialTheme.typography.bodySmall,
            color = MaterialTheme.colorScheme.onSurfaceVariant,
            maxLines = 1,
            overflow = TextOverflow.Ellipsis
        )
        Text(
            text = value,
            modifier = Modifier.weight(1f),
            style = MaterialTheme.typography.bodySmall
        )
    }
}
