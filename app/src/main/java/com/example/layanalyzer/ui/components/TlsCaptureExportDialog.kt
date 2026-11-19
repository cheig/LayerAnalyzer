// Copyright (c) 2026 cheig; GPL-3.0.
package com.example.layanalyzer.ui.components

import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.verticalScroll
import androidx.compose.foundation.selection.selectable
import androidx.compose.material3.AlertDialog
import androidx.compose.material3.Checkbox
import androidx.compose.material3.RadioButton
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Modifier
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.semantics.Role
import androidx.compose.ui.Alignment
import androidx.compose.ui.unit.dp
import com.example.layanalyzer.R
import com.example.layanalyzer.data.TlsCaptureExportKind
import com.example.layanalyzer.data.TlsCaptureExportPlan

@Composable
internal fun TlsCaptureExportDialog(
    filtered: Boolean,
    onExport: (TlsCaptureExportKind, Boolean) -> Unit,
    onDismiss: () -> Unit
) {
    var kind by remember { mutableStateOf(TlsCaptureExportPlan.defaultKind) }
    var confirmed by remember { mutableStateOf(false) }
    val complete = kind == TlsCaptureExportKind.CompleteDecryptableSession
    AlertDialog(
        onDismissRequest = onDismiss,
        title = { Text(stringResource(R.string.tls_capture_export_title)) },
        text = {
            Column(Modifier.verticalScroll(rememberScrollState())) {
                TlsCaptureExportKind.entries.forEach { option ->
                    val label = when (option) {
                        TlsCaptureExportKind.OriginalCapture -> R.string.tls_capture_export_original
                        TlsCaptureExportKind.CompleteDecryptableSession -> R.string.tls_capture_export_complete
                        TlsCaptureExportKind.SelectedPlaintext -> R.string.tls_capture_export_plaintext
                    }
                    Row(Modifier.fillMaxWidth().selectable(kind == option, role = Role.RadioButton, onClick = {
                        kind = option
                        confirmed = false
                    }).padding(vertical = 8.dp), verticalAlignment = Alignment.CenterVertically) {
                        RadioButton(selected = kind == option, onClick = null)
                        Text(stringResource(label))
                    }
                }
                Text(stringResource(when (kind) {
                    TlsCaptureExportKind.OriginalCapture -> R.string.tls_capture_export_original_hint
                    TlsCaptureExportKind.CompleteDecryptableSession -> R.string.tls_capture_export_warning
                    TlsCaptureExportKind.SelectedPlaintext -> R.string.tls_capture_export_plaintext_hint
                }))
                if (complete) {
                    if (filtered) Text(stringResource(R.string.tls_capture_export_filtered_warning))
                    Row(verticalAlignment = Alignment.CenterVertically) {
                        Checkbox(confirmed, onCheckedChange = { confirmed = it })
                        Text(stringResource(R.string.tls_capture_export_confirm))
                    }
                }
            }
        },
        confirmButton = {
            TextButton(enabled = !complete || confirmed && !filtered, onClick = { onExport(kind, confirmed) }) {
                Text(stringResource(if (kind == TlsCaptureExportKind.SelectedPlaintext)
                    R.string.tls_capture_export_choose_content else R.string.tls_capture_export_save))
            }
        },
        dismissButton = { TextButton(onClick = onDismiss) { Text(stringResource(R.string.cancel)) } }
    )
}
