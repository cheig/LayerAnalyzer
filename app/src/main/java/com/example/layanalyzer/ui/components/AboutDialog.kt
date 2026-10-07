// Copyright (c) 2026 cheig
// LayerAnalyzer - https://github.com/cheig/LayerAnalyzer
// Licensed under GNU GPL version 3; see LICENSE.

package com.example.layanalyzer.ui.components

import android.widget.Toast
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.text.selection.SelectionContainer
import androidx.compose.foundation.verticalScroll
import androidx.compose.material3.AlertDialog
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalClipboardManager
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.platform.LocalUriHandler
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.text.AnnotatedString
import androidx.compose.ui.unit.dp
import com.example.layanalyzer.BuildConfig
import com.example.layanalyzer.R

@Composable
internal fun AboutDialog(
    onOpenNotices: () -> Unit,
    onDismiss: () -> Unit
) {
    val context = LocalContext.current
    val clipboard = LocalClipboardManager.current
    val uriHandler = LocalUriHandler.current
    val projectUrl = stringResource(R.string.project_repository_url)

    AlertDialog(
        onDismissRequest = onDismiss,
        title = { Text(stringResource(R.string.about_title)) },
        text = {
            Column(
                modifier = Modifier.verticalScroll(rememberScrollState()),
                verticalArrangement = Arrangement.spacedBy(12.dp)
            ) {
                Text(
                    stringResource(R.string.about_version, BuildConfig.VERSION_NAME, BuildConfig.VERSION_CODE),
                    style = MaterialTheme.typography.bodyMedium
                )
                SelectionContainer {
                    Column(verticalArrangement = Arrangement.spacedBy(8.dp)) {
                        Text(
                            stringResource(R.string.about_author, stringResource(R.string.project_author)),
                            style = MaterialTheme.typography.titleSmall
                        )
                        Text(stringResource(R.string.project_copyright))
                        Text(stringResource(R.string.about_repository), style = MaterialTheme.typography.labelLarge)
                        Text(projectUrl, color = MaterialTheme.colorScheme.primary)
                    }
                }
                TextButton(onClick = {
                    try {
                        uriHandler.openUri(projectUrl)
                    } catch (_: IllegalArgumentException) {
                        Toast.makeText(context, R.string.about_browser_unavailable, Toast.LENGTH_LONG).show()
                    }
                }) {
                    Text(stringResource(R.string.about_open_repository))
                }
                TextButton(onClick = {
                    clipboard.setText(AnnotatedString(projectUrl))
                    Toast.makeText(context, R.string.about_repository_copied, Toast.LENGTH_SHORT).show()
                }) {
                    Text(stringResource(R.string.about_copy_repository))
                }
                Text(stringResource(R.string.about_license_summary), style = MaterialTheme.typography.bodySmall)
                Text(stringResource(R.string.about_third_party_summary), style = MaterialTheme.typography.bodySmall)
                TextButton(onClick = onOpenNotices) {
                    Text(stringResource(R.string.about_license_notices))
                }
            }
        },
        confirmButton = {
            TextButton(onClick = onDismiss) { Text(stringResource(R.string.close)) }
        }
    )
}
