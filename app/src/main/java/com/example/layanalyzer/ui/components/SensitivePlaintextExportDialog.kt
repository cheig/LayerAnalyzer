// Copyright (c) 2026 cheig; GPL-3.0.
package com.example.layanalyzer.ui.components

import androidx.compose.foundation.layout.Column
import androidx.compose.material3.AlertDialog
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.ui.res.stringResource
import com.example.layanalyzer.R

/** No export callback runs until the user has seen its actual content scope. */
@Composable
internal fun SensitivePlaintextExportDialog(scope: String, onConfirm: () -> Unit, onDismiss: () -> Unit) {
    AlertDialog(
        onDismissRequest = onDismiss,
        title = { Text(stringResource(R.string.tls_plaintext_export_title)) },
        text = { Column {
            Text(scope)
            Text(stringResource(R.string.tls_plaintext_export_warning))
        } },
        confirmButton = { TextButton(onConfirm) { Text(stringResource(R.string.tls_plaintext_export_confirm)) } },
        dismissButton = { TextButton(onDismiss) { Text(stringResource(R.string.cancel)) } }
    )
}
