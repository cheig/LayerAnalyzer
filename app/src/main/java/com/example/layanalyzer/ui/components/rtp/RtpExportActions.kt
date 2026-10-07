// Copyright (c) 2026 cheig
// LayerAnalyzer - https://github.com/cheig/LayerAnalyzer
// Licensed under GNU GPL version 3; see LICENSE.

package com.example.layanalyzer.ui.components.rtp

import android.content.Context
import android.content.Intent
import android.net.Uri
import androidx.activity.compose.ManagedActivityResultLauncher
import androidx.activity.compose.rememberLauncherForActivityResult
import androidx.activity.result.contract.ActivityResultContracts
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.widthIn
import androidx.compose.material3.AlertDialog
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.runtime.remember
import androidx.compose.ui.Modifier
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.dp
import com.example.layanalyzer.R
import com.example.layanalyzer.media.ExternalPlayerLauncher
import com.example.layanalyzer.model.ExportResult
import com.example.layanalyzer.model.RtpCodecCatalog
import com.example.layanalyzer.model.RtpDecodability
import com.example.layanalyzer.model.RtpExportFormat
import com.example.layanalyzer.model.RtpStream
import com.example.layanalyzer.model.rtpExportFileName
import com.example.layanalyzer.model.rtpRawExtension
import com.example.layanalyzer.model.rtpRawFileName
import com.example.layanalyzer.model.rtpWavFileName
import com.example.layanalyzer.viewmodel.RtpExportDestination
import java.io.File

/** WAV export file name used by the SAF CreateDocument flow. */
fun rtpWavExportFileName(stream: RtpStream): String = rtpWavFileName(stream)

/** Raw payload extension used by the SAF CreateDocument flow. */
fun rtpRawExportExtension(codec: String): String? = rtpRawExtension(codec)

/** Raw payload file name, or null when the codec has no M2 raw representation. */
fun rtpRawExportFileName(stream: RtpStream): String? = rtpRawFileName(stream)

/**
 * RTP4-KT-03：一种导出格式的文件名；该格式在这条流上不成立时为 null
 * （`WAV` 恒有名字，`RAW`/容器看编码）。
 */
fun rtpFormatExportFileName(stream: RtpStream, format: RtpExportFormat): String? =
    rtpExportFileName(stream, format)

/**
 * RTP4-KT-03：这条流在导出格式菜单里应该出现哪些按钮。
 *
 * 取 `RtpCodecCatalog.exportFormats(stream.codec)`（卡片「编码 → 可用格式」表，表住在
 * catalog 里）再按这条流的实际状态筛一遍：只有**真的导得出来**的格式才留下，菜单里
 * 不会出现按下去必然失败的按钮。筛选口径与 `performExport` 的前置 `check` 一致：
 * 三条路径都要求 `decodable == yes`，裸流另要求编码有裸流后缀。
 *
 * 顺序按 [RtpExportFormat] 的声明顺序（WAV → 裸流 → 容器），与集合的实现无关。
 */
fun rtpExportableFormats(stream: RtpStream): List<RtpExportFormat> {
    if (stream.decodable != RtpDecodability.YES) return emptyList()
    return RtpCodecCatalog.exportFormats(stream.codec)
        .filter { format ->
            when (format) {
                RtpExportFormat.WAV -> true
                RtpExportFormat.RAW -> rtpRawExportFileName(stream) != null
                else -> RtpCodecCatalog.containerFormat(stream.codec) == format
            }
        }
        .sortedBy { it.ordinal }
}

/** 导出格式的显示名（RTP4-KT-03，文案两个 `strings.xml` 都有）。 */
@Composable
fun rtpExportFormatLabel(format: RtpExportFormat): String = stringResource(
    when (format) {
        RtpExportFormat.WAV -> R.string.rtp_export_format_wav
        RtpExportFormat.RAW -> R.string.rtp_export_format_raw
        RtpExportFormat.AMR -> R.string.rtp_export_format_amr
        RtpExportFormat.AWB -> R.string.rtp_export_format_awb
        RtpExportFormat.OPUS -> R.string.rtp_export_format_opus
    }
)

/** Reusable CreateDocument launcher for `audio/wav`. */
@Composable
fun rememberRtpWavExportLauncher(
    onResult: (Uri?) -> Unit
): ManagedActivityResultLauncher<String, Uri?> =
    rememberLauncherForActivityResult(
        ActivityResultContracts.CreateDocument("audio/wav"),
        onResult
    )

/** Reusable CreateDocument launcher for raw RTP payloads. */
@Composable
fun rememberRtpRawExportLauncher(
    onResult: (Uri?) -> Unit
): ManagedActivityResultLauncher<String, Uri?> =
    rememberLauncherForActivityResult(
        ActivityResultContracts.CreateDocument("application/octet-stream"),
        onResult
    )

/**
 * RTP4-KT-03：按导出格式创建的 CreateDocument launcher。
 *
 * `CreateDocument` 的 MIME 在构造时就固定，所以每个格式各建一个 —— [format] 只用来
 * 取 [RtpExportFormat.mimeType]，调用方对需要的格式**无条件**地各调一次（不要放进
 * if/循环，那会违反 `remember` 的调用规则）。
 */
@Composable
fun rememberRtpFormatExportLauncher(
    format: RtpExportFormat,
    onResult: (Uri?) -> Unit
): ManagedActivityResultLauncher<String, Uri?> =
    rememberLauncherForActivityResult(
        ActivityResultContracts.CreateDocument(format.mimeType),
        onResult
    )

/**
 * RTP4-KT-03：导出格式对话框。
 *
 * 列出 [rtpExportableFormats] 里的格式，选一个交回宿主（宿主负责选 SAF 目的地并调用
 * ViewModel 的 `exportFormat`）。一个格式都没有时明确说明，不静默留空。
 */
@Composable
fun RtpExportFormatDialog(
    stream: RtpStream,
    onSelect: (RtpExportFormat) -> Unit,
    onDismiss: () -> Unit
) {
    val formats = remember(stream.id, stream.codec, stream.decodable) {
        rtpExportableFormats(stream)
    }
    AlertDialog(
        onDismissRequest = onDismiss,
        title = {
            Text(
                stringResource(R.string.rtp_export_format_title),
                maxLines = 1,
                overflow = TextOverflow.Ellipsis
            )
        },
        text = {
            if (formats.isEmpty()) {
                Text(stringResource(R.string.rtp_export_format_none))
            } else {
                Column(modifier = Modifier.widthIn(max = 560.dp)) {
                    formats.forEach { format ->
                        OutlinedButton(
                            onClick = { onSelect(format) },
                            modifier = Modifier
                                .fillMaxWidth()
                                .padding(top = 4.dp)
                        ) {
                            Text(
                                rtpExportFormatLabel(format),
                                maxLines = 1,
                                overflow = TextOverflow.Ellipsis
                            )
                        }
                    }
                }
            }
        },
        confirmButton = {
            TextButton(onClick = onDismiss) {
                Text(stringResource(R.string.close))
            }
        }
    )
}

/**
 * Builds a ViewModel export destination backed by the SAF URI returned from
 * [rememberRtpWavExportLauncher] or [rememberRtpRawExportLauncher].
 */
fun rtpExportDestination(
    context: Context,
    uri: Uri,
    displayName: String
): RtpExportDestination = RtpExportDestination(displayName) { source ->
    try {
        val output = context.contentResolver.openOutputStream(uri, "w")
            ?: error(context.getString(R.string.rtp_export_destination_error))
        output.use { destination ->
            source.inputStream().use { input -> input.copyTo(destination) }
        }
    } catch (error: Throwable) {
        runCatching { context.contentResolver.delete(uri, null, null) }
        throw error
    }
}

/**
 * Shares one or more cached RTP export files. A single file uses ACTION_SEND;
 * a multi-stream export uses ACTION_SEND_MULTIPLE with the same FileProvider
 * grants.
 */
fun shareRtpExportResults(context: Context, results: List<ExportResult>) {
    if (results.isEmpty()) return
    val uris = results.map { result ->
        ExternalPlayerLauncher.uriFor(context, File(result.filePath))
    }
    val intent = if (uris.size == 1) {
        Intent(Intent.ACTION_SEND).apply {
            type = results.single().mimeType
            putExtra(Intent.EXTRA_STREAM, uris.single())
            putExtra(Intent.EXTRA_TITLE, results.single().displayName)
        }
    } else {
        Intent(Intent.ACTION_SEND_MULTIPLE).apply {
            type = results.map(ExportResult::mimeType).distinct().singleOrNull() ?: "*/*"
            putParcelableArrayListExtra(Intent.EXTRA_STREAM, ArrayList(uris))
            putExtra(
                Intent.EXTRA_TITLE,
                results.joinToString(separator = ", ") { it.displayName }
            )
        }
    }.apply {
        addFlags(Intent.FLAG_GRANT_READ_URI_PERMISSION)
    }
    ExternalPlayerLauncher.grantReadPermission(context, intent, uris)
    context.startActivity(
        Intent.createChooser(
            intent,
            context.getString(R.string.rtp_share_export_chooser_title)
        ).addFlags(Intent.FLAG_ACTIVITY_NEW_TASK)
    )
}
