// Copyright (c) 2026 cheig
// LayerAnalyzer - https://github.com/cheig/LayerAnalyzer
// Licensed under GNU GPL version 3; see LICENSE.

package com.example.layanalyzer.ui.components

import androidx.annotation.StringRes
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.ExperimentalLayoutApi
import androidx.compose.foundation.layout.FlowRow
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.width
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.Close
import androidx.compose.material3.AssistChip
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.RadioButton
import androidx.compose.material3.Switch
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
import com.example.layanalyzer.capture.tls.TlsCaState
import com.example.layanalyzer.model.QuicPolicy
import com.example.layanalyzer.model.TlsCaptureSettings
import com.example.layanalyzer.model.TlsHostScope
import com.example.layanalyzer.model.TlsSettingsIssueCode
import com.example.layanalyzer.model.TlsSettingsValidation

/**
 * The observable capability state of TLS decryption at settings time (TLS-304
 * step 3). It is deliberately *not* a claim that interception works: a build
 * without the engine, a CA that is not installed and an IPv6 path that is not
 * captured are three different, separately stated limitations.
 *
 * `caState == null` means "not read yet", which shows as nothing rather than as
 * ready. `quicInterceptionAvailable` is the forwarding-layer UDP rule shipping
 * (TLS-314): it is true in a build that can intercept at all, because the rule
 * only exists to send an application back to a TCP connection this build would
 * intercept — so a build without the engine keeps the control disabled.
 */
internal data class TlsSettingsStatus(
    val featureBuilt: Boolean,
    val caState: TlsCaState?,
    val ipv6Captured: Boolean,
    val quicInterceptionAvailable: Boolean = false
)

/**
 * One statement about the UDP/443 intervention that is *true of this
 * configuration* (TLS-314). Each entry has exactly one sentence of user-facing
 * text; [tlsQuicNotices] decides which of them apply, so the choice can be
 * asserted without a renderer.
 */
internal enum class TlsQuicNotice(@StringRes val messageRes: Int, val blocking: Boolean = false) {
    /** The rule itself, stated exactly: port, direction and address families. */
    RULE(R.string.tls_capture_quic_rule),

    /**
     * What the rule does to the user's traffic: this is intervention, not
     * decryption, and a client that does not fall back simply loses QUIC.
     */
    IMPACT(R.string.tls_capture_quic_impact),

    /** IPv6 is not captured, so the block cannot cover that path. */
    IPV6_BYPASS(R.string.tls_capture_quic_ipv6_bypass),

    /** The scope cannot be expressed at the forwarding layer; the mode is refused. */
    SCOPE_UNDECIDABLE(R.string.tls_capture_quic_scope_undecidable, blocking = true),

    /** No forwarding-layer rule exists in this build. */
    NOT_AVAILABLE(R.string.tls_capture_quic_disabled_reason)
}

/**
 * Which QUIC statements to show for a draft. Pure on purpose: the branch that
 * decides "IPv6 is not captured, so the block does not cover it" is a claim about
 * scope, and a claim that is wrong is worse than no text at all.
 *
 * The order is fixed — availability, then the rule, then its consequences — so a
 * reader never sees an impact statement for a rule that was refused.
 */
internal fun tlsQuicNotices(
    settings: TlsCaptureSettings,
    status: TlsSettingsStatus,
    validation: TlsSettingsValidation
): List<TlsQuicNotice> = buildList {
    if (!status.quicInterceptionAvailable) add(TlsQuicNotice.NOT_AVAILABLE)
    if (!settings.enabled || settings.quicPolicy != QuicPolicy.BlockSelectedUdp443) return@buildList
    if (validation.issues.any { it.code == TlsSettingsIssueCode.QUIC_SCOPE_UNDECIDABLE }) {
        // The mode is refused, so its rule and its impact are not promises; the
        // requirement that is missing is what the user needs to read (step 2).
        add(TlsQuicNotice.SCOPE_UNDECIDABLE)
        return@buildList
    }
    add(TlsQuicNotice.RULE)
    add(TlsQuicNotice.IMPACT)
    if (!status.ipv6Captured) add(TlsQuicNotice.IPV6_BYPASS)
}

/**
 * The TLS decryption block of the VPN capture settings (design §10.1/§12).
 *
 * Stateless: the draft lives with the caller, [validation] is the single
 * [com.example.layanalyzer.model.TlsCaptureSettingsValidator] result for the
 * current draft and every control reflects it — this composable never validates
 * a second way. [enabled] is false while a capture is running, so a change can
 * never be mistaken for applying to the current run (design §10.3).
 */
@Composable
@OptIn(ExperimentalLayoutApi::class)
internal fun TlsCaptureSettingsSection(
    settings: TlsCaptureSettings,
    status: TlsSettingsStatus,
    validation: TlsSettingsValidation,
    enabled: Boolean,
    onSettingsChange: (TlsCaptureSettings) -> Unit,
    /**
     * Opens the CA install wizard (TLS-305). Null hides the entry, so a caller
     * that has not wired the wizard keeps the section exactly as before.
     */
    onOpenCertificateSetup: (() -> Unit)? = null,
    onOpenUsageHelp: (() -> Unit)? = null
) {
    Column(Modifier.fillMaxWidth()) {
        Text(stringResource(R.string.tls_capture_title), style = MaterialTheme.typography.titleSmall)
        Text(
            stringResource(R.string.tls_capture_description),
            style = MaterialTheme.typography.bodySmall,
            color = MaterialTheme.colorScheme.onSurfaceVariant
        )
        TlsUsageHelpButton(onOpenUsageHelp)
        Spacer(Modifier.height(6.dp))

        TlsCapabilityNotices(status, settings.enabled)

        if (onOpenCertificateSetup != null) {
            // The wizard is reachable whenever the engine is built, so a CA can be
            // set up before interception is switched on. It still cannot generate
            // without the engine, so it is disabled when the feature is absent.
            TextButton(onClick = onOpenCertificateSetup, enabled = status.featureBuilt) {
                Text(stringResource(R.string.tls_ca_setup_open))
            }
        }

        Row(verticalAlignment = Alignment.CenterVertically, modifier = Modifier.fillMaxWidth()) {
            Text(stringResource(R.string.tls_capture_enable), modifier = Modifier.weight(1f))
            Switch(
                checked = settings.enabled,
                enabled = enabled,
                onCheckedChange = { onSettingsChange(settings.copy(enabled = it)) }
            )
        }

        if (settings.enabled) {
            Spacer(Modifier.height(4.dp))
            Text(
                stringResource(R.string.tls_capture_scope_label),
                style = MaterialTheme.typography.labelLarge
            )
            TlsScopeOption(
                label = stringResource(R.string.tls_capture_scope_explicit),
                description = stringResource(R.string.tls_capture_scope_explicit_description),
                selected = settings.hostScope == TlsHostScope.ExplicitHosts,
                enabled = enabled
            ) { onSettingsChange(settings.copy(hostScope = TlsHostScope.ExplicitHosts)) }
            TlsScopeOption(
                label = stringResource(R.string.tls_capture_scope_selected_apps),
                description = stringResource(R.string.tls_capture_scope_selected_apps_description),
                selected = settings.hostScope == TlsHostScope.SelectedApplicationsCandidates,
                enabled = enabled
            ) { onSettingsChange(settings.copy(hostScope = TlsHostScope.SelectedApplicationsCandidates)) }

            Spacer(Modifier.height(8.dp))
            TlsHostRuleList(
                label = stringResource(R.string.tls_capture_include_label),
                description = stringResource(R.string.tls_capture_include_description),
                rules = settings.includeHosts,
                enabled = enabled,
                onAdd = { onSettingsChange(settings.copy(includeHosts = (settings.includeHosts + it).distinct())) },
                onRemove = { onSettingsChange(settings.copy(includeHosts = settings.includeHosts - it)) }
            )

            Spacer(Modifier.height(8.dp))
            TlsHostRuleList(
                label = stringResource(R.string.tls_capture_bypass_label),
                description = stringResource(R.string.tls_capture_bypass_description),
                rules = settings.bypassHosts,
                enabled = enabled,
                onAdd = { onSettingsChange(settings.copy(bypassHosts = (settings.bypassHosts + it).distinct())) },
                onRemove = { onSettingsChange(settings.copy(bypassHosts = settings.bypassHosts - it)) }
            )

            Spacer(Modifier.height(8.dp))
            TlsPortList(
                ports = settings.candidatePorts,
                enabled = enabled,
                onChange = { onSettingsChange(settings.copy(candidatePorts = it)) }
            )

            Spacer(Modifier.height(8.dp))
            Row(verticalAlignment = Alignment.CenterVertically, modifier = Modifier.fillMaxWidth()) {
                Column(Modifier.weight(1f)) {
                    Text(stringResource(R.string.tls_capture_quic_label))
                    // Every statement here is decided by tlsQuicNotices, so the
                    // displayed rule and the applied rule come from one place
                    // (TLS-314 steps 1/3/4).
                    tlsQuicNotices(settings, status, validation).forEach { notice ->
                        Text(
                            stringResource(notice.messageRes),
                            style = MaterialTheme.typography.labelSmall,
                            color = if (notice.blocking) {
                                MaterialTheme.colorScheme.error
                            } else {
                                MaterialTheme.colorScheme.onSurfaceVariant
                            },
                            modifier = Modifier.padding(top = 2.dp)
                        )
                    }
                }
                Switch(
                    checked = settings.quicPolicy == QuicPolicy.BlockSelectedUdp443,
                    // The rule exists in this build and edits are allowed (TLS-314
                    // step 1); an invalid scope does not hide the control — it is
                    // reported under it and refuses the start (step 2).
                    enabled = status.quicInterceptionAvailable && enabled,
                    onCheckedChange = { onSettingsChange(settings.copy(
                        quicPolicy = if (it) QuicPolicy.BlockSelectedUdp443 else QuicPolicy.Preserve
                    )) }
                )
            }

            Spacer(Modifier.height(4.dp))
            Row(verticalAlignment = Alignment.CenterVertically, modifier = Modifier.fillMaxWidth()) {
                Column(Modifier.weight(1f)) {
                    Text(stringResource(R.string.tls_capture_retain_secrets))
                    Text(
                        stringResource(R.string.tls_capture_retain_secrets_description),
                        style = MaterialTheme.typography.labelSmall,
                        color = MaterialTheme.colorScheme.onSurfaceVariant
                    )
                }
                Switch(
                    checked = settings.retainSecrets,
                    enabled = enabled,
                    onCheckedChange = { onSettingsChange(settings.copy(retainSecrets = it)) }
                )
            }

            TlsValidationIssues(validation)
        }
    }
}

/** Capability and scope limitations, stated only when they actually apply. */
@Composable
private fun TlsCapabilityNotices(status: TlsSettingsStatus, tlsEnabled: Boolean) {
    val notices = buildList {
        if (!status.featureBuilt) add(stringResource(R.string.tls_capture_feature_unavailable))
        if (!status.ipv6Captured) add(stringResource(R.string.tls_capture_ipv6_not_captured))
        if (tlsEnabled) tlsCaStateReason(status.caState)?.let(::add)
    }
    notices.forEach { notice ->
        Text(
            notice,
            style = MaterialTheme.typography.labelSmall,
            color = MaterialTheme.colorScheme.onSurfaceVariant,
            modifier = Modifier.padding(top = 2.dp)
        )
    }
}

@Composable
private fun tlsCaStateReason(state: TlsCaState?): String? = when (state) {
    null, TlsCaState.READY -> null
    TlsCaState.MISSING -> stringResource(R.string.tls_capture_ca_missing)
    TlsCaState.EXPIRED -> stringResource(R.string.tls_capture_ca_expired)
    TlsCaState.NOT_YET_VALID -> stringResource(R.string.tls_capture_ca_not_yet_valid)
    TlsCaState.KEY_UNAVAILABLE -> stringResource(R.string.tls_capture_ca_key_unavailable)
    TlsCaState.INVALID_FORMAT -> stringResource(R.string.tls_capture_ca_invalid_format)
    TlsCaState.IO_ERROR -> stringResource(R.string.tls_capture_ca_io_error)
}

@Composable
private fun TlsScopeOption(
    label: String,
    description: String,
    selected: Boolean,
    enabled: Boolean,
    onSelect: () -> Unit
) {
    Row(verticalAlignment = Alignment.CenterVertically, modifier = Modifier.fillMaxWidth()) {
        RadioButton(selected = selected, onClick = onSelect, enabled = enabled)
        Column(Modifier.weight(1f)) {
            Text(label)
            Text(
                description,
                style = MaterialTheme.typography.labelSmall,
                color = MaterialTheme.colorScheme.onSurfaceVariant
            )
        }
    }
}

@Composable
@OptIn(ExperimentalLayoutApi::class)
private fun TlsHostRuleList(
    label: String,
    description: String,
    rules: List<String>,
    enabled: Boolean,
    onAdd: (String) -> Unit,
    onRemove: (String) -> Unit
) {
    var input by remember { mutableStateOf("") }
    Column(Modifier.fillMaxWidth()) {
        Text(label, style = MaterialTheme.typography.labelLarge)
        Text(
            description,
            style = MaterialTheme.typography.labelSmall,
            color = MaterialTheme.colorScheme.onSurfaceVariant
        )
        Row(verticalAlignment = Alignment.CenterVertically, modifier = Modifier.fillMaxWidth()) {
            OutlinedTextField(
                value = input,
                onValueChange = { input = it },
                singleLine = true,
                enabled = enabled,
                modifier = Modifier.weight(1f)
            )
            Spacer(Modifier.width(6.dp))
            TextButton(
                onClick = {
                    val value = input.trim()
                    if (value.isNotEmpty()) {
                        onAdd(value)
                        input = ""
                    }
                },
                enabled = enabled && input.isNotBlank()
            ) { Text(stringResource(R.string.tls_capture_rule_add)) }
        }
        if (rules.isNotEmpty()) {
            FlowRow(horizontalArrangement = Arrangement.spacedBy(6.dp)) {
                rules.forEach { rule ->
                    AssistChip(
                        onClick = { if (enabled) onRemove(rule) },
                        label = {
                            Text(rule, fontFamily = FontFamily.Monospace, maxLines = 1, overflow = TextOverflow.Ellipsis)
                        },
                        trailingIcon = {
                            Icon(
                                Icons.Default.Close,
                                contentDescription = stringResource(R.string.remove_rule),
                                modifier = Modifier.width(16.dp)
                            )
                        }
                    )
                }
            }
        }
    }
}

@Composable
@OptIn(ExperimentalLayoutApi::class)
private fun TlsPortList(
    ports: Set<Int>,
    enabled: Boolean,
    onChange: (Set<Int>) -> Unit
) {
    var input by remember { mutableStateOf("") }
    Column(Modifier.fillMaxWidth()) {
        Text(stringResource(R.string.tls_capture_ports_label), style = MaterialTheme.typography.labelLarge)
        Text(
            stringResource(R.string.tls_capture_ports_description),
            style = MaterialTheme.typography.labelSmall,
            color = MaterialTheme.colorScheme.onSurfaceVariant
        )
        Row(verticalAlignment = Alignment.CenterVertically, modifier = Modifier.fillMaxWidth()) {
            OutlinedTextField(
                value = input,
                onValueChange = { input = it },
                singleLine = true,
                enabled = enabled,
                modifier = Modifier.weight(1f)
            )
            Spacer(Modifier.width(6.dp))
            TextButton(
                onClick = {
                    // The range is decided by TlsCaptureSettingsValidator, not here: an
                    // out-of-range port is added and reported as INVALID_PORT.
                    input.trim().toIntOrNull()?.let { onChange(ports + it) }
                    input = ""
                },
                enabled = enabled && input.trim().toIntOrNull() != null
            ) { Text(stringResource(R.string.tls_capture_rule_add)) }
        }
        if (ports.isNotEmpty()) {
            FlowRow(horizontalArrangement = Arrangement.spacedBy(6.dp)) {
                ports.sorted().forEach { port ->
                    AssistChip(
                        onClick = { if (enabled) onChange(ports - port) },
                        label = { Text(port.toString(), fontFamily = FontFamily.Monospace) },
                        trailingIcon = {
                            Icon(
                                Icons.Default.Close,
                                contentDescription = stringResource(R.string.remove_rule),
                                modifier = Modifier.width(16.dp)
                            )
                        }
                    )
                }
            }
        }
    }
}

@Composable
private fun TlsValidationIssues(validation: TlsSettingsValidation) {
    if (validation.isValid) return
    Spacer(Modifier.height(4.dp))
    Text(
        stringResource(R.string.tls_capture_invalid_settings),
        style = MaterialTheme.typography.labelMedium,
        color = MaterialTheme.colorScheme.error
    )
    // Fixed codes and field names only; the rejected rule text is never echoed (C04).
    validation.issues.forEach { issue ->
        val field = issue.index?.let { "${issue.field}[$it]" } ?: issue.field
        Text(
            stringResource(R.string.tls_capture_issue, issue.code.wireName, field),
            style = MaterialTheme.typography.labelSmall,
            color = MaterialTheme.colorScheme.error
        )
    }
}
