// Copyright (c) 2026 cheig
// LayerAnalyzer - https://github.com/cheig/LayerAnalyzer
// Licensed under GNU GPL version 3; see LICENSE.

package com.example.layanalyzer.ui.components

import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.material3.HorizontalDivider
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
import androidx.compose.ui.unit.dp
import com.example.layanalyzer.R
import com.example.layanalyzer.capture.tls.TlsConnectionSnapshot
import com.example.layanalyzer.model.TlsConnectionPhase
import com.example.layanalyzer.viewmodel.TlsConnectionFailureExplanation
import com.example.layanalyzer.viewmodel.TlsConnectionDetail
import com.example.layanalyzer.viewmodel.TlsConnectionKeyState
import com.example.layanalyzer.viewmodel.TlsConnectionSummary
import com.example.layanalyzer.viewmodel.TlsConnectionUiProjection
import com.example.layanalyzer.viewmodel.TlsFrameAssociationUi
import java.text.SimpleDateFormat
import java.util.Date
import java.util.Locale

/**
 * The TLS half of the live-capture preview (TLS-306, design 搂10.2).
 *
 * It is a stateless renderer of two ViewModel values: the store snapshot and the
 * projected [TlsConnectionSummary]. Both are published at most once per C10's
 * 250 ms gate, so nothing here can cause a per-byte recomposition.
 *
 * The section deliberately states the limits of its own numbers:
 *
 *  * the "verified decryptable" count is annotated as pending analysis, because a
 *    completed proxy handshake is not a decryption (C03 7);
 *  * QUIC is shown as untracked rather than as zero, and is never in the failure
 *    count (UDP/443 is forwarded unchanged until TLS-314);
 *  * when the reader fell behind, the summary says it may be low.
 *
 * The jump to a capture frame is offered only for a real, correlated frame:
 * every other association renders a disabled control, so an unassociated
 * connection can never pretend to have a frame number.
 */
@Composable
internal fun TlsConnectionPreviewSection(
    snapshot: TlsConnectionSnapshot?,
    summary: TlsConnectionSummary?,
    onJumpToFrame: (Long) -> Unit,
    modifier: Modifier = Modifier
) {
    Column(modifier = modifier.fillMaxWidth()) {
        if (snapshot == null || summary == null) {
            Text(
                stringResource(R.string.tls_connection_preview_disabled),
                style = MaterialTheme.typography.bodySmall,
                color = MaterialTheme.colorScheme.onSurfaceVariant
            )
        } else {

            Text(stringResource(R.string.tls_connection_summary_title), style = MaterialTheme.typography.titleSmall)
            Text(
                stringResource(
                    R.string.tls_connection_summary_line_1,
                    summary.proxied,
                    summary.secretsSaved,
                    summary.decrypted
                ),
                style = MaterialTheme.typography.labelMedium,
                color = MaterialTheme.colorScheme.onSurface
            )
            Text(
                stringResource(
                    R.string.tls_connection_summary_line_2,
                    summary.passthrough,
                    summary.handshakeFailed,
                    summary.failed
                ),
                style = MaterialTheme.typography.labelMedium,
                color = MaterialTheme.colorScheme.onSurface
            )
            if (summary.decryptionPendingAnalysis) {
                Text(
                    stringResource(R.string.tls_connection_decrypted_pending),
                    style = MaterialTheme.typography.labelSmall,
                    color = MaterialTheme.colorScheme.onSurfaceVariant
                )
            }
            if (!summary.quic.tracked) {
                Text(
                    stringResource(R.string.tls_connection_quic_untracked),
                    style = MaterialTheme.typography.labelSmall,
                    color = MaterialTheme.colorScheme.onSurfaceVariant
                )
            }
            if (summary.secretsIncomplete > 0L) {
                Text(
                    stringResource(R.string.tls_connection_secrets_incomplete, summary.secretsIncomplete),
                    style = MaterialTheme.typography.labelSmall,
                    color = MaterialTheme.colorScheme.onSurfaceVariant
                )
            }
            summary.handshakeCapacityPassthrough?.takeIf { it > 0L }?.let { count ->
                Text(
                    stringResource(R.string.tls_connection_handshake_capacity_bypass, count),
                    style = MaterialTheme.typography.labelSmall,
                    color = MaterialTheme.colorScheme.onSurfaceVariant
                )
            }
            if (summary.eventHistoryEvicted > 0L) {
                Text(
                    stringResource(R.string.tls_connection_history_evicted, summary.eventHistoryEvicted),
                    style = MaterialTheme.typography.labelSmall,
                    color = MaterialTheme.colorScheme.onSurfaceVariant
                )
            }
            if (summary.countersIncomplete) {
                Text(
                    stringResource(
                        R.string.tls_connection_counters_incomplete,
                        summary.eventsDropped,
                        summary.eventsRejected,
                        summary.eventsNotPersisted
                    ),
                    style = MaterialTheme.typography.labelSmall,
                    color = MaterialTheme.colorScheme.error
                )
            }

            HorizontalDivider(Modifier.padding(vertical = 8.dp))
            Text(stringResource(R.string.tls_connection_details_title), style = MaterialTheme.typography.titleSmall)
            // 搂8.4: the proxy's loopback hop carries no UID, so no connection can be
            // attributed to an app. Stated once here so no row implies otherwise.
            Text(
                stringResource(R.string.tls_connection_app_unknown),
                style = MaterialTheme.typography.labelSmall,
                color = MaterialTheme.colorScheme.onSurfaceVariant
            )
            val details = remember(snapshot) { TlsConnectionUiProjection.details(snapshot) }
            if (details.isEmpty()) {
                Text(
                    stringResource(R.string.tls_connection_details_empty),
                    style = MaterialTheme.typography.bodySmall,
                    color = MaterialTheme.colorScheme.onSurfaceVariant
                )
            } else {
                details.forEach { detail -> TlsConnectionDetailRow(detail, onJumpToFrame) }
            }
        }
    }
}

@Composable
private fun TlsConnectionDetailRow(detail: TlsConnectionDetail, onJumpToFrame: (Long) -> Unit) {
    // Expansion is keyed by connection so a re-publish (new snapshot object) does
    // not collapse a row the user opened.
    var expanded by remember(detail.connectionId) { mutableStateOf(false) }
    Column(Modifier.fillMaxWidth().padding(vertical = 4.dp)) {
        Row(Modifier.fillMaxWidth(), verticalAlignment = Alignment.CenterVertically) {
            Column(Modifier.weight(1f)) {
                Text(
                    detail.destination,
                    fontFamily = FontFamily.Monospace,
                    style = MaterialTheme.typography.labelLarge
                )
                Text(
                    stringResource(R.string.tls_connection_phase, phaseLabel(detail.phase)),
                    style = MaterialTheme.typography.labelSmall,
                    color = MaterialTheme.colorScheme.onSurfaceVariant
                )
            }
            TextButton(onClick = { expanded = !expanded }) {
                Text(
                    stringResource(
                        if (expanded) R.string.tls_connection_collapse else R.string.tls_connection_expand
                    )
                )
            }
        }
        if (expanded) TlsConnectionDetailBody(detail, onJumpToFrame)
        HorizontalDivider()
    }
}

@Composable
private fun TlsConnectionDetailBody(detail: TlsConnectionDetail, onJumpToFrame: (Long) -> Unit) {
    Column(Modifier.fillMaxWidth().padding(start = 8.dp, bottom = 4.dp)) {
        DetailLine(stringResource(R.string.tls_connection_time, formatWallTime(detail.wallTimeMillis)))
        DetailLine(
            detail.sni?.let { stringResource(R.string.tls_connection_sni, it) }
                ?: stringResource(R.string.tls_connection_sni_unknown)
        )
        DetailLine(
            stringResource(
                R.string.tls_connection_downstream_tls,
                detail.downstreamTls ?: stringResource(R.string.tls_connection_tls_unknown)
            )
        )
        DetailLine(
            stringResource(
                R.string.tls_connection_upstream_tls,
                detail.upstreamTls ?: stringResource(R.string.tls_connection_tls_unknown)
            )
        )
        DetailLine(
            detail.alpn?.let { stringResource(R.string.tls_connection_alpn, it) }
                ?: stringResource(R.string.tls_connection_alpn_unknown)
        )
        DetailLine(
            if (detail.upstreamCertificateVerified) {
                stringResource(
                    R.string.tls_connection_upstream_cert,
                    detail.upstreamCertificateSha256.orEmpty()
                )
            } else {
                stringResource(R.string.tls_connection_upstream_cert_unknown)
            }
        )
        detail.decisionReason?.let { reason ->
            DetailLine(stringResource(R.string.tls_connection_decision, reason))
        }
        DetailLine(keyStateLabel(detail))
        detail.errorCode?.let { code ->
            DetailLine(stringResource(R.string.tls_connection_error, code.wireName), isError = true)
            errorExplanation(detail.failureExplanation)?.let { DetailLine(it, isError = true) }
        }
        FrameAssociationLine(detail, onJumpToFrame)
    }
}

@Composable
private fun FrameAssociationLine(detail: TlsConnectionDetail, onJumpToFrame: (Long) -> Unit) {
    when (val frame = detail.frame) {
        is TlsFrameAssociationUi.Matched -> {
            DetailLine(
                if (frame.helloRetryRequest) {
                    stringResource(
                        R.string.tls_connection_frame_hrr,
                        frame.globalFrameNumber,
                        frame.clientHelloFrames
                    )
                } else {
                    stringResource(R.string.tls_connection_frame, frame.globalFrameNumber)
                }
            )
            TextButton(onClick = { onJumpToFrame(frame.globalFrameNumber) }) {
                Text(stringResource(R.string.tls_connection_jump))
            }
        }
        is TlsFrameAssociationUi.Unmatched -> {
            DetailLine(stringResource(R.string.tls_connection_frame_unmatched, frame.reason.name))
            DisabledJump()
        }
        TlsFrameAssociationUi.NotCorrelated -> {
            DetailLine(stringResource(R.string.tls_connection_frame_not_correlated))
            DisabledJump()
        }
    }
}

@Composable
private fun DisabledJump() {
    TextButton(onClick = {}, enabled = false) {
        Text(stringResource(R.string.tls_connection_jump))
    }
}

@Composable
private fun DetailLine(text: String, isError: Boolean = false) {
    Text(
        text,
        style = MaterialTheme.typography.labelSmall,
        color = if (isError) MaterialTheme.colorScheme.error else MaterialTheme.colorScheme.onSurfaceVariant,
        modifier = Modifier.fillMaxWidth()
    )
}

@Composable
private fun phaseLabel(phase: TlsConnectionPhase): String = stringResource(
    when (phase) {
        TlsConnectionPhase.ACCEPTED -> R.string.tls_phase_accepted
        TlsConnectionPhase.SNIFFING -> R.string.tls_phase_sniffing
        TlsConnectionPhase.UPSTREAM_HANDSHAKE -> R.string.tls_phase_upstream_handshake
        TlsConnectionPhase.DOWNSTREAM_HANDSHAKE -> R.string.tls_phase_downstream_handshake
        TlsConnectionPhase.RELAYING -> R.string.tls_phase_relaying
        TlsConnectionPhase.PASSTHROUGH -> R.string.tls_phase_passthrough
        TlsConnectionPhase.CLOSED -> R.string.tls_phase_closed
        TlsConnectionPhase.FAILED -> R.string.tls_phase_failed
        TlsConnectionPhase.UNKNOWN -> R.string.tls_phase_unknown
    }
)

@Composable
private fun keyStateLabel(detail: TlsConnectionDetail): String = when (detail.keyState) {
    TlsConnectionKeyState.NONE -> stringResource(R.string.tls_connection_keys_none)
    TlsConnectionKeyState.SAVED ->
        stringResource(R.string.tls_connection_keys_saved, detail.secretRecordsPersisted)
    TlsConnectionKeyState.INCOMPLETE ->
        stringResource(
            R.string.tls_connection_keys_incomplete,
            detail.secretRecordsPersisted,
            detail.secretRecordsAccepted
        )
}

/** Render only fixed explanations derived from code and reason, never platform error text. */
@Composable
private fun errorExplanation(explanation: TlsConnectionFailureExplanation?): String? = when (explanation) {
    TlsConnectionFailureExplanation.DOWNSTREAM_CLOSED -> stringResource(R.string.tls_connection_error_downstream_closed)
    TlsConnectionFailureExplanation.DOWNSTREAM_TIMEOUT -> stringResource(R.string.tls_connection_error_downstream_timeout)
    TlsConnectionFailureExplanation.DOWNSTREAM_HANDSHAKE -> stringResource(R.string.tls_connection_error_downstream_handshake)
    TlsConnectionFailureExplanation.DOWNSTREAM_ALERT -> stringResource(R.string.tls_connection_error_downstream_alert)
    TlsConnectionFailureExplanation.DOWNSTREAM_UNCLASSIFIED -> stringResource(R.string.tls_connection_error_downstream_rejected)
    TlsConnectionFailureExplanation.UPSTREAM_CERTIFICATE -> stringResource(R.string.tls_connection_error_upstream_cert_invalid)
    TlsConnectionFailureExplanation.SECRETS_INCOMPLETE -> stringResource(R.string.tls_connection_error_secrets_incomplete)
    TlsConnectionFailureExplanation.CAPTURE_CONTEXT_MISSING -> stringResource(R.string.tls_connection_error_capture_context_missing)
    TlsConnectionFailureExplanation.CANCELLED -> stringResource(R.string.tls_connection_error_cancelled)
    null -> null
}

@Composable
private fun formatWallTime(millis: Long): String {
    if (millis <= 0L) return stringResource(R.string.tls_connection_time_unknown)
    val formatter = remember { SimpleDateFormat("HH:mm:ss.SSS", Locale.getDefault()) }
    return formatter.format(Date(millis))
}
