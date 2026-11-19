// Copyright (c) 2026 cheig; GPL-3.0.
package com.example.layanalyzer.ui.components

import androidx.compose.foundation.layout.*
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.verticalScroll
import androidx.compose.material3.*
import androidx.compose.runtime.Composable
import androidx.compose.ui.Modifier
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.unit.dp
import com.example.layanalyzer.R
import com.example.layanalyzer.viewmodel.TlsKeyLogImportPhase
import com.example.layanalyzer.viewmodel.TlsKeyLogImportState

@Composable
internal fun TlsKeyLogImportDialog(
    state: TlsKeyLogImportState,
    hasCapture: Boolean,
    onImport: () -> Unit,
    onClear: () -> Unit,
    onCancel: () -> Unit,
    onDismiss: () -> Unit
) {
    AlertDialog(
        onDismissRequest = { if (!state.busy) onDismiss() },
        title = { Text(stringResource(R.string.tls_keylog_title)) },
        text = {
            Column(Modifier.fillMaxWidth().verticalScroll(rememberScrollState()),
                verticalArrangement = Arrangement.spacedBy(12.dp)) {
                Text(stringResource(R.string.tls_keylog_description))
                TlsUsageHelpButton()
                Text(stringResource(if (state.configured) R.string.tls_keylog_configured else R.string.tls_keylog_not_configured))
                Text(stringResource(if (state.observedDecryptedData) R.string.tls_keylog_observed else R.string.tls_keylog_not_observed))
                // What the verdict is made of. Connections, not frames: one connection is
                // one decryption, and the version is the one its plaintext arrived under.
                if (state.observedDecryptedData) {
                    val stats = state.plaintextStats
                    Text(stringResource(R.string.tls_keylog_plaintext_totals,
                        stats.connections, stats.tls13Connections, stats.tls12Connections,
                        stats.otherConnections, stats.decryptedRecords, stats.decryptedBytes))
                }
                if (state.importedRecords > 0) Text(stringResource(R.string.tls_keylog_counts,
                    state.importedRecords, state.duplicateLines, state.unsupportedLines))
                if (state.busy) {
                    Text(stringResource(when (state.phase) {
                        TlsKeyLogImportPhase.Selecting -> R.string.tls_keylog_selecting
                        TlsKeyLogImportPhase.Reading -> R.string.tls_keylog_reading
                        TlsKeyLogImportPhase.Saving -> R.string.tls_keylog_saving
                        TlsKeyLogImportPhase.Cancelling -> R.string.tls_keylog_cancelling
                        else -> R.string.tls_keylog_reparsing
                    }))
                    if (state.totalFrames > 0) {
                        LinearProgressIndicator(progress = { state.processedFrames.toFloat() / state.totalFrames },
                            modifier = Modifier.fillMaxWidth())
                        Text(stringResource(R.string.tls_keylog_frames, state.processedFrames, state.totalFrames))
                    } else LinearProgressIndicator(Modifier.fillMaxWidth())
                    Text(stringResource(R.string.tls_keylog_cancel_note))
                }
                state.parseError?.let {
                    Text(stringResource(R.string.tls_keylog_invalid, it.lineNumber, it.code.name),
                        color = MaterialTheme.colorScheme.error)
                }
                state.errorCode?.let { code ->
                    Text(if (code == "UNSUPPORTED") stringResource(R.string.tls_keylog_unsupported)
                        else stringResource(R.string.tls_keylog_error, code), color = MaterialTheme.colorScheme.error)
                }
                if (state.cancelled) Text(stringResource(R.string.tls_keylog_cancelled))
                if (state.reopenRequired) Text(stringResource(R.string.error_tls_reopen_capture))
                if (!state.busy) {
                    Button(onClick = onImport, enabled = hasCapture, modifier = Modifier.fillMaxWidth()) {
                        Text(stringResource(R.string.tls_keylog_import))
                    }
                    OutlinedButton(onClick = onClear, enabled = hasCapture && state.configured,
                        modifier = Modifier.fillMaxWidth()) { Text(stringResource(R.string.tls_keylog_clear)) }
                }
            }
        },
        confirmButton = {
            if (state.busy) TextButton(onClick = onCancel,
                enabled = state.phase != TlsKeyLogImportPhase.Cancelling) { Text(stringResource(R.string.cancel)) }
            else TextButton(onClick = onDismiss) { Text(stringResource(R.string.close)) }
        }
    )
}
