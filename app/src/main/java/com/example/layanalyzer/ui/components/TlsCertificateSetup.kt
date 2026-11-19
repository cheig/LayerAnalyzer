// Copyright (c) 2026 cheig
// LayerAnalyzer - https://github.com/cheig/LayerAnalyzer
// Licensed under GNU GPL version 3; see LICENSE.

package com.example.layanalyzer.ui.components

import android.app.Activity
import android.content.Intent
import android.os.Build
import android.provider.Settings
import android.security.KeyChain
import androidx.activity.compose.rememberLauncherForActivityResult
import androidx.activity.result.contract.ActivityResultContracts
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.heightIn
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.verticalScroll
import androidx.compose.material3.AlertDialog
import androidx.compose.material3.Button
import androidx.compose.material3.HorizontalDivider
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.rememberCoroutineScope
import androidx.compose.runtime.setValue
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.unit.dp
import com.example.layanalyzer.R
import com.example.layanalyzer.capture.tls.TlsCaExportPlan
import com.example.layanalyzer.capture.tls.TlsCaInstallObservation
import com.example.layanalyzer.capture.tls.TlsCaInstallPlan
import com.example.layanalyzer.capture.tls.TlsCaInstallRoute
import com.example.layanalyzer.capture.tls.TlsCaManagerHolder
import com.example.layanalyzer.capture.tls.TlsCaPublicExport
import com.example.layanalyzer.capture.tls.TlsCaState
import com.example.layanalyzer.capture.tls.TlsCaStatus
import com.example.layanalyzer.capture.tls.TlsCaUiOperations
import com.example.layanalyzer.capture.tls.TlsCertificateErrorCode
import com.example.layanalyzer.capture.tls.TlsCertificateException
import com.example.layanalyzer.capture.tls.TlsFixtureTestStatus
import com.example.layanalyzer.capture.tls.TlsTargetAppStatus
import java.text.SimpleDateFormat
import java.util.Date
import java.util.Locale
import kotlinx.coroutines.launch

/** The MIME type SAF is asked to suggest for the exported `.cer` file. */
private const val TLS_CA_MIME_TYPE = "application/x-x509-ca-cert"

/**
 * The CA install wizard (design §7.3, TLS-305).
 *
 * It shows the published CA's name, fingerprint and validity, exports only the
 * public `.cer`, installs via the system certificate installer on API 26–29 or
 * guides the user to settings on API 30+, and reports what was actually observed.
 *
 * It never claims more than it knows:
 *  - a completed system installer is "the dialog was completed", not "trusted"
 *    (the system user-CA store is not queryable and a completed dialog is not a
 *    trust decision by any app, §7.3.3);
 *  - the in-app fixture test and the target-app connection are shown as
 *    not-run/unknown because nothing here observes them;
 *  - `reset` still goes through the process-wide manager, so it is refused
 *    (`CAPTURE_ACTIVE`) while a capture holds a lease.
 */
@Composable
internal fun TlsCertificateSetupDialog(
    captureRunning: Boolean,
    onDismiss: () -> Unit
) {
    val context = LocalContext.current
    val scope = rememberCoroutineScope()
    val operations = remember(context) {
        TlsCaUiOperations(TlsCaManagerHolder.get(context))
    }

    var status by remember { mutableStateOf<TlsCaStatus?>(null) }
    var exported by remember { mutableStateOf<TlsCaPublicExport?>(null) }
    var busy by remember { mutableStateOf(false) }
    var errorCode by remember { mutableStateOf<TlsCertificateErrorCode?>(null) }
    var installObservation by remember { mutableStateOf(TlsCaInstallObservation.NOT_ATTEMPTED) }
    var exportMessage by remember { mutableStateOf<Int?>(null) }
    var confirmingReset by remember { mutableStateOf(false) }

    // The CA read touches the filesystem and the Keystore, so it is off the main
    // thread. A read never generates or resets anything.
    LaunchedEffect(Unit) {
        status = try {
            operations.refresh()
        } catch (error: TlsCertificateException) {
            errorCode = error.code
            null
        }
    }

    val exportLauncher = rememberLauncherForActivityResult(
        ActivityResultContracts.CreateDocument(TLS_CA_MIME_TYPE)
    ) { uri ->
        val data = exported
        if (uri == null || data == null) return@rememberLauncherForActivityResult
        val written = runCatching {
            context.contentResolver.openOutputStream(uri)?.use { output ->
                // Public DER only; TlsCertificateManager.exportPublicCertificate
                // returns no private key. Nothing else ever reaches this output.
                output.write(data.certificateDer)
                output.flush()
            } != null
        }.getOrDefault(false)
        exportMessage = if (written) R.string.tls_ca_setup_export_done else R.string.tls_ca_setup_export_failed
        if (written) exported = null
    }

    val installLauncher = rememberLauncherForActivityResult(
        ActivityResultContracts.StartActivityForResult()
    ) { result ->
        // RESULT_OK is "the system dialog completed", nothing more (§7.3.3).
        installObservation = TlsCaInstallPlan.observationForResult(result.resultCode == Activity.RESULT_OK)
    }

    fun run(block: suspend () -> Unit) {
        scope.launch {
            busy = true
            errorCode = null
            try {
                block()
            } catch (error: TlsCertificateException) {
                errorCode = error.code
            } finally {
                busy = false
            }
        }
    }

    fun launchExport() = run {
        exportMessage = null
        val data = operations.export()
        exported = data
        exportLauncher.launch(TlsCaExportPlan.suggestedFileName(data.caId))
    }

    fun launchInstall() = run {
        when (TlsCaInstallPlan.routeFor(Build.VERSION.SDK_INT)) {
            TlsCaInstallRoute.SystemInstallIntent -> {
                val data = exported ?: operations.export().also { exported = it }
                val intent = KeyChain.createInstallIntent().apply {
                    putExtra(KeyChain.EXTRA_CERTIFICATE, data.certificateDer)
                    putExtra(KeyChain.EXTRA_NAME, data.subjectName)
                }
                if (intent.resolveActivity(context.packageManager) != null) {
                    installLauncher.launch(intent)
                } else {
                    // No installer resolved: report the honest "no result", never
                    // "installed". The user can still install from settings.
                    installObservation = TlsCaInstallPlan.observationForGuidance()
                }
            }
            // API 30+ must not call createInstallIntent() to pretend to install a
            // CA; the system settings is the only route, and it has no result.
            TlsCaInstallRoute.SettingsGuidance ->
                installObservation = TlsCaInstallPlan.observationForGuidance()
        }
    }

    val state = status?.state
    val exportable = state != null && state != TlsCaState.MISSING

    AlertDialog(
        onDismissRequest = { if (!busy) onDismiss() },
        title = { Text(stringResource(R.string.tls_ca_setup_title)) },
        text = {
            Column(
                Modifier.fillMaxWidth().heightIn(max = 520.dp).verticalScroll(rememberScrollState()),
                verticalArrangement = Arrangement.spacedBy(6.dp)
            ) {
                Text(stringResource(R.string.tls_ca_setup_description), style = MaterialTheme.typography.bodySmall)

                HorizontalDivider(Modifier.padding(vertical = 4.dp))
                TlsCaStatusBlock(status)

                HorizontalDivider(Modifier.padding(vertical = 4.dp))
                Button(
                    onClick = { run { status = operations.generate() } },
                    // Only a missing CA is generated; a damaged or unusable one is
                    // recovered with reset, exactly like TlsCertificateManager says.
                    enabled = !busy && (state == null || state == TlsCaState.MISSING),
                    modifier = Modifier.fillMaxWidth()
                ) { Text(stringResource(R.string.tls_ca_setup_generate)) }

                OutlinedButton(
                    onClick = { launchExport() },
                    enabled = !busy && exportable,
                    modifier = Modifier.fillMaxWidth()
                ) { Text(stringResource(R.string.tls_ca_setup_export)) }
                Text(
                    stringResource(R.string.tls_ca_setup_export_description),
                    style = MaterialTheme.typography.labelSmall,
                    color = MaterialTheme.colorScheme.onSurfaceVariant
                )
                exportMessage?.let { Text(stringResource(it), style = MaterialTheme.typography.labelSmall) }

                OutlinedButton(
                    onClick = { launchInstall() },
                    enabled = !busy && exportable,
                    modifier = Modifier.fillMaxWidth()
                ) { Text(stringResource(R.string.tls_ca_setup_install)) }
                Text(
                    stringResource(
                        when (TlsCaInstallPlan.routeFor(Build.VERSION.SDK_INT)) {
                            TlsCaInstallRoute.SystemInstallIntent -> R.string.tls_ca_setup_install_legacy_hint
                            TlsCaInstallRoute.SettingsGuidance -> R.string.tls_ca_setup_install_modern_hint
                        }
                    ),
                    style = MaterialTheme.typography.labelSmall,
                    color = MaterialTheme.colorScheme.onSurfaceVariant
                )
                TextButton(
                    onClick = { runCatching { context.startActivity(Intent(Settings.ACTION_SECURITY_SETTINGS)) } },
                    enabled = !busy
                ) { Text(stringResource(R.string.tls_ca_setup_open_settings)) }

                HorizontalDivider(Modifier.padding(vertical = 4.dp))
                TlsCaReturnedStatuses(
                    installObservation = installObservation,
                    fixture = TlsFixtureTestStatus.NOT_RUN,
                    target = TlsTargetAppStatus.UNKNOWN
                )

                HorizontalDivider(Modifier.padding(vertical = 4.dp))
                Text(
                    stringResource(R.string.tls_ca_setup_trust_scope_notice),
                    style = MaterialTheme.typography.labelSmall,
                    color = MaterialTheme.colorScheme.onSurfaceVariant
                )
                status?.let { current ->
                    if (current.systemStoreRemovalRequired) {
                        Text(
                            stringResource(R.string.tls_ca_setup_previous_ca_notice),
                            style = MaterialTheme.typography.labelSmall,
                            color = MaterialTheme.colorScheme.error
                        )
                    }
                }

                // A running capture freezes its own configuration, so the CA must
                // not be replaced under it: the button is disabled here *and* the
                // manager refuses with CAPTURE_ACTIVE below. Disabling it matters
                // because a capture without TLS interception holds no lease, so
                // the manager alone would let the reset through while the notice
                // above still claimed it was blocked.
                TextButton(onClick = { confirmingReset = true }, enabled = !busy && !captureRunning) {
                    Text(stringResource(R.string.tls_ca_setup_reset))
                }
                if (captureRunning) {
                    Text(
                        stringResource(R.string.tls_ca_setup_reset_blocked),
                        style = MaterialTheme.typography.labelSmall,
                        color = MaterialTheme.colorScheme.error
                    )
                }
                errorCode?.let { code ->
                    Text(
                        stringResource(
                            if (code == TlsCertificateErrorCode.CAPTURE_ACTIVE) R.string.tls_ca_setup_reset_blocked
                            else R.string.tls_ca_setup_error, code.name
                        ),
                        style = MaterialTheme.typography.labelSmall,
                        color = MaterialTheme.colorScheme.error
                    )
                }
                if (busy) Text(stringResource(R.string.tls_ca_setup_busy), style = MaterialTheme.typography.labelSmall)
            }
        },
        confirmButton = {
            TextButton(onClick = onDismiss, enabled = !busy) { Text(stringResource(R.string.close)) }
        }
    )

    if (confirmingReset) {
        AlertDialog(
            onDismissRequest = { confirmingReset = false },
            title = { Text(stringResource(R.string.tls_ca_setup_reset_confirm_title)) },
            text = { Text(stringResource(R.string.tls_ca_setup_reset_confirm)) },
            confirmButton = {
                Button(onClick = {
                    confirmingReset = false
                    run {
                        status = operations.reset()
                        exported = null
                        exportMessage = null
                        installObservation = TlsCaInstallObservation.NOT_ATTEMPTED
                    }
                }) { Text(stringResource(R.string.tls_ca_setup_reset)) }
            },
            dismissButton = {
                TextButton(onClick = { confirmingReset = false }) { Text(stringResource(R.string.cancel)) }
            }
        )
    }
}

@Composable
private fun TlsCaStatusBlock(status: TlsCaStatus?) {
    val state = status?.state
    Row(Modifier.fillMaxWidth()) {
        Text(
            stringResource(R.string.tls_ca_setup_state_label),
            modifier = Modifier.weight(1f),
            style = MaterialTheme.typography.labelLarge
        )
        Text(tlsCaStateText(state), style = MaterialTheme.typography.bodySmall)
    }
    if (status == null) return
    status.subjectName?.let {
        Text(
            stringResource(R.string.tls_ca_setup_subject, it),
            style = MaterialTheme.typography.labelSmall,
            fontFamily = FontFamily.Monospace
        )
    }
    status.certificateSha256?.let {
        Text(
            stringResource(R.string.tls_ca_setup_fingerprint, formatFingerprint(it)),
            style = MaterialTheme.typography.labelSmall,
            fontFamily = FontFamily.Monospace
        )
    }
    if (status.notBeforeMillis != null && status.notAfterMillis != null) {
        Text(
            stringResource(
                R.string.tls_ca_setup_validity,
                formatDate(status.notBeforeMillis), formatDate(status.notAfterMillis)
            ),
            style = MaterialTheme.typography.labelSmall
        )
    }
}

@Composable
private fun TlsCaReturnedStatuses(
    installObservation: TlsCaInstallObservation,
    fixture: TlsFixtureTestStatus,
    target: TlsTargetAppStatus
) {
    TlsCaStatusLine(R.string.tls_ca_setup_install_label, installObservationText(installObservation))
    TlsCaStatusLine(
        R.string.tls_ca_setup_fixture_label,
        stringResource(when (fixture) {
            TlsFixtureTestStatus.NOT_RUN -> R.string.tls_ca_setup_fixture_not_run
            TlsFixtureTestStatus.PASSED -> R.string.tls_ca_setup_fixture_passed
            TlsFixtureTestStatus.FAILED -> R.string.tls_ca_setup_fixture_failed
        })
    )
    TlsCaStatusLine(
        R.string.tls_ca_setup_target_label,
        stringResource(when (target) {
            TlsTargetAppStatus.UNKNOWN -> R.string.tls_ca_setup_target_unknown
            TlsTargetAppStatus.CONNECTED -> R.string.tls_ca_setup_target_connected
            TlsTargetAppStatus.FAILED -> R.string.tls_ca_setup_target_failed
        })
    )
}

@Composable
private fun TlsCaStatusLine(labelRes: Int, value: String) {
    Column(Modifier.fillMaxWidth().padding(vertical = 1.dp)) {
        Text(stringResource(labelRes), style = MaterialTheme.typography.labelMedium)
        Text(value, style = MaterialTheme.typography.labelSmall, color = MaterialTheme.colorScheme.onSurfaceVariant)
    }
}

@Composable
private fun tlsCaStateText(state: TlsCaState?): String = stringResource(
    when (state) {
        null, TlsCaState.MISSING -> R.string.tls_capture_ca_missing
        TlsCaState.READY -> R.string.tls_ca_setup_state_ready
        TlsCaState.EXPIRED -> R.string.tls_capture_ca_expired
        TlsCaState.NOT_YET_VALID -> R.string.tls_capture_ca_not_yet_valid
        TlsCaState.KEY_UNAVAILABLE -> R.string.tls_capture_ca_key_unavailable
        TlsCaState.INVALID_FORMAT -> R.string.tls_capture_ca_invalid_format
        TlsCaState.IO_ERROR -> R.string.tls_capture_ca_io_error
    }
)

@Composable
private fun installObservationText(observation: TlsCaInstallObservation): String = stringResource(
    when (observation) {
        TlsCaInstallObservation.NOT_ATTEMPTED -> R.string.tls_ca_setup_install_not_attempted
        TlsCaInstallObservation.SYSTEM_DIALOG_COMPLETED -> R.string.tls_ca_setup_install_completed
        TlsCaInstallObservation.SYSTEM_DIALOG_CANCELLED -> R.string.tls_ca_setup_install_cancelled
        TlsCaInstallObservation.NO_OBSERVABLE_RESULT -> R.string.tls_ca_setup_install_no_result
    }
)

private fun formatFingerprint(hex: String): String =
    hex.lowercase(Locale.ROOT).chunked(2).joinToString(":").uppercase(Locale.ROOT)

private fun formatDate(millis: Long): String =
    SimpleDateFormat("yyyy-MM-dd", Locale.US).format(Date(millis))
