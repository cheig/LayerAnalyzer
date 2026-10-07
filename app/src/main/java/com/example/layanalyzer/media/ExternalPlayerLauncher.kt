// Copyright (c) 2026 cheig
// LayerAnalyzer - https://github.com/cheig/LayerAnalyzer
// Licensed under GNU GPL version 3; see LICENSE.

package com.example.layanalyzer.media

import android.app.Activity
import android.content.ActivityNotFoundException
import android.content.Context
import android.content.Intent
import android.net.Uri
import androidx.annotation.StringRes
import androidx.core.content.FileProvider
import com.example.layanalyzer.R
import java.io.File

object ExternalPlayerLauncher {
    /**
     * Opens [file] with a compatible external app.
     *
     * @param chooserTitleRes the chooser's title. It defaults to the WAV title because
     * that was this function's only caller until RTP5-UI-01; the video path passes its
     * own, since "Open WAV with" would be a plain lie about a `.h264` file.
     * @return true when the chooser was launched, or false when no app can
     * handle the requested MIME type. The `false` return is the hook RTP4-KT-03
     * hangs its WAV fallback on: a container MIME (`audio/amr`, `audio/amr-wb`,
     * `audio/ogg`) that nothing on the device claims is not an error, it is the
     * signal to try a more widely supported representation.
     */
    fun open(
        context: Context,
        file: File,
        mimeType: String,
        @StringRes chooserTitleRes: Int = R.string.rtp_open_external_chooser_title
    ): Boolean {
        val uri = uriFor(context, file)
        val viewIntent = Intent(Intent.ACTION_VIEW).apply {
            setDataAndType(uri, mimeType)
            addFlags(Intent.FLAG_GRANT_READ_URI_PERMISSION)
        }
        if (context.packageManager.queryIntentActivities(viewIntent, 0).isEmpty()) {
            return false
        }
        grantReadPermission(context, viewIntent, listOf(uri))

        val chooser = Intent.createChooser(
            viewIntent,
            context.getString(chooserTitleRes)
        ).apply {
            addFlags(Intent.FLAG_GRANT_READ_URI_PERMISSION)
            if (context !is Activity) {
                addFlags(Intent.FLAG_ACTIVITY_NEW_TASK)
            }
        }

        return try {
            context.startActivity(chooser)
            true
        } catch (_: ActivityNotFoundException) {
            false
        }
    }

    /**
     * RTP4-KT-03: 一个「外部打开」候选 —— 文件与它的 MIME。
     *
     * 顺序就是回退顺序：原生容器（`.amr`/`.awb`/`.opus`，系统播放器能直接播）排在
     * 前面，WAV 排在后面。
     */
    data class ExternalOpenCandidate(val file: File, val mimeType: String)

    /**
     * 依次尝试 [candidates]，返回第一个真正打开的目标；一个都打不开时返回 `null`。
     *
     * 只把 [open] 的 `false`（没有任何应用能处理该 MIME）当作「试下一个」的条件；
     * `open` 内部已经吞掉的 `ActivityNotFoundException` 是同一件事的另一种表现。
     * 其它异常一律不吞（`open` 本身也不会抛）。
     *
     * [chooserTitleRes] 交给每一次尝试（见 [open]）。
     */
    fun openFirstAvailable(
        context: Context,
        candidates: List<ExternalOpenCandidate>,
        @StringRes chooserTitleRes: Int = R.string.rtp_open_external_chooser_title
    ): ExternalOpenCandidate? {
        for (candidate in candidates) {
            if (open(context, candidate.file, candidate.mimeType, chooserTitleRes)) {
                return candidate
            }
        }
        return null
    }

    /** Returns a shareable content URI for a file under the app cache. */
    fun uriFor(context: Context, file: File): Uri =
        FileProvider.getUriForFile(
            context,
            "${context.packageName}.fileprovider",
            file
        )

    /**
     * Explicitly grants a provider URI to every activity that can receive
     * [intent]. Some OEM chooser implementations do not propagate
     * FLAG_GRANT_READ_URI_PERMISSION to the selected target.
     */
    internal fun grantReadPermission(
        context: Context,
        intent: Intent,
        uris: List<Uri>
    ) {
        if (uris.isEmpty()) return
        val resolveIntent = Intent(intent).apply {
            addFlags(Intent.FLAG_GRANT_READ_URI_PERMISSION)
        }
        context.packageManager.queryIntentActivities(resolveIntent, 0)
            .map { it.activityInfo.packageName }
            .distinct()
            .forEach { packageName ->
                uris.forEach { uri ->
                    runCatching {
                        context.grantUriPermission(
                            packageName,
                            uri,
                            Intent.FLAG_GRANT_READ_URI_PERMISSION
                        )
                    }
                }
            }
    }
}
