// Copyright (c) 2026 cheig
// LayerAnalyzer - https://github.com/cheig/LayerAnalyzer
// Licensed under GNU GPL version 3; see LICENSE.

package com.example.layanalyzer.ui.components

import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.heightIn
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.verticalScroll
import androidx.compose.material3.AlertDialog
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.saveable.rememberSaveable
import androidx.compose.runtime.setValue
import androidx.compose.ui.Modifier
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.unit.dp
import com.example.layanalyzer.R

/** Offline help shared by VPN settings and passive keylog import (TLS-407). */
@Composable
internal fun TlsUsageHelpButton(onOpen: (() -> Unit)? = null) {
    var expanded by rememberSaveable { mutableStateOf(false) }
    TextButton(onClick = { if (onOpen != null) onOpen() else expanded = true }) {
        Text(stringResource(R.string.tls_usage_help_title))
    }
    if (expanded) TlsUsageHelpDialog { expanded = false }
}

@Composable
internal fun TlsUsageHelpDialog(onDismiss: () -> Unit) {
    AlertDialog(
        onDismissRequest = onDismiss,
        title = { Text(stringResource(R.string.tls_usage_help_title)) },
        text = {
            Column(
                modifier = Modifier.fillMaxWidth().heightIn(max = 480.dp)
                    .verticalScroll(rememberScrollState()),
                verticalArrangement = Arrangement.spacedBy(12.dp)
            ) {
                Text(stringResource(R.string.tls_usage_help_status))
                listOf(
                    R.string.tls_usage_help_prepare_title to R.string.tls_usage_help_prepare,
                    R.string.tls_usage_help_ca_title to R.string.tls_usage_help_ca,
                    R.string.tls_usage_help_capture_title to R.string.tls_usage_help_capture,
                    R.string.tls_usage_help_analysis_title to R.string.tls_usage_help_analysis,
                    R.string.tls_usage_help_export_title to R.string.tls_usage_help_export,
                    R.string.tls_usage_help_cleanup_title to R.string.tls_usage_help_cleanup,
                    R.string.tls_usage_help_limits_title to R.string.tls_usage_help_limits,
                    R.string.tls_usage_help_errors_title to R.string.tls_usage_help_errors
                ).forEach { (title, body) ->
                    Text(stringResource(title), style = MaterialTheme.typography.titleSmall)
                    Text(stringResource(body), style = MaterialTheme.typography.bodyMedium)
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
