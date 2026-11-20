// Copyright (c) 2026 cheig
// LayerAnalyzer - https://github.com/cheig/LayerAnalyzer
// Licensed under GNU GPL version 3; see LICENSE.

package com.example.layanalyzer.capture

import com.example.layanalyzer.capture.tls.TlsCaState
import com.example.layanalyzer.model.TlsCaptureSettings
import com.example.layanalyzer.model.TlsCaptureStatus

/**
 * Why an enabled TLS capture was not started (TLS-315 step 1, design §10.3).
 *
 * These are start conditions, not runtime failures: each one is decided *before*
 * the service is asked to run, and none of them may produce a capture state that
 * looks like a running interception (acceptance 2). They never apply to a
 * TLS-disabled configuration — the ordinary flow keeps no gate at all (C03 1).
 *
 * Public because it is shown by the settings screen (the ViewModel's refusal state
 * and the composable parameter that renders it both name it).
 */
enum class TlsStartBlockReason {
    /** TLS is on but the configuration the validator rejects cannot be frozen (C04). */
    CONFIGURATION_INVALID,

    /** TLS interception is not compiled into this build. */
    FEATURE_UNAVAILABLE,

    /** The local CA is missing, unusable or unread: the wizard has to be run first. */
    CA_NOT_READY,

    /** Not enough free storage to run a TLS capture safely. */
    STORAGE_LOW
}

/** The verdict of [TlsStartGate.evaluate]. */
internal sealed interface TlsStartReadiness {
    /** The run may proceed; the caller still freezes the configuration itself. */
    data object Ready : TlsStartReadiness

    /** The run must not be offered to the service at all. */
    data class Blocked(val reason: TlsStartBlockReason) : TlsStartReadiness
}

/**
 * The environment facts a start decision depends on. They are inputs, never read
 * here, so the decision is host-testable without a device, a Keystore or a
 * filesystem.
 *
 * [caState] is the CA state as read (`TlsCertificateManager.status().state`). It is
 * null only when nothing has been read yet, and an unread CA is deliberately *not*
 * treated as installed: starting with interception on mints a root no application
 * has been asked to trust, which is exactly the silent full-range capture step 1
 * forbids.
 */
internal data class TlsStartFacts(
    val featureBuilt: Boolean,
    val caState: TlsCaState?,
    val freeBytes: Long
)

/**
 * The one place that decides whether an enabled TLS configuration may start
 * (TLS-315 step 1).
 *
 * A TLS-disabled configuration is always [TlsStartReadiness.Ready]: turning the
 * feature off must change nothing about the existing network forwarding, and the
 * settings screen's CA entry must not become a gate (C03 1, acceptance 2). Only an
 * enabled configuration is checked, and each refusal names the one thing the user
 * has to fix, in the same order the design lists them.
 */
internal object TlsStartGate {
    /**
     * The floor below which a TLS capture is refused.
     *
     * It is not a C10 budget: C10 fixes protocol and queue limits, not free space.
     * The smallest segment the settings allow is 32 MiB (`segmentSizeMegabytes` 32)
     * and the writer needs the segment plus the tail of the previous one, so 64 MiB
     * is the point below which "the capture will run" is not a statement this build
     * can honestly make. The check is a start sanity gate, not a space reservation.
     */
    const val MIN_FREE_BYTES: Long = 64L * 1024L * 1024L

    fun evaluate(
        tls: TlsCaptureSettings,
        configurationValid: Boolean,
        facts: TlsStartFacts
    ): TlsStartReadiness {
        if (!tls.enabled) return TlsStartReadiness.Ready
        if (!configurationValid) return TlsStartReadiness.Blocked(TlsStartBlockReason.CONFIGURATION_INVALID)
        if (!facts.featureBuilt) return TlsStartReadiness.Blocked(TlsStartBlockReason.FEATURE_UNAVAILABLE)
        if (facts.caState != TlsCaState.READY) return TlsStartReadiness.Blocked(TlsStartBlockReason.CA_NOT_READY)
        if (facts.freeBytes < MIN_FREE_BYTES) return TlsStartReadiness.Blocked(TlsStartBlockReason.STORAGE_LOW)
        return TlsStartReadiness.Ready
    }
}

/**
 * What the capture notification says about TLS (TLS-315 step 3). It is a
 * degradation vocabulary, not a progress one: this build can honestly state
 * "interception is up", "new connections are no longer decrypted" and "it did not
 * run", and nothing else.
 */
internal enum class CaptureNotificationTlsState {
    /** The run does not intercept TLS at all. */
    NOT_INTERCEPTING,

    /** Interception is up and the sink has not refused or lost a record. */
    INTERCEPTING,

    /**
     * Interception is up but a secret could no longer be written, so new
     * connections are passed through and only established ones keep working
     * (design §8.2, C03 7).
     */
    DEGRADED,

    /** Interception was requested and is not running. */
    FAILED
}

/**
 * Maps a run's TLS state onto the notification vocabulary (TLS-315 step 3).
 *
 * A status the mapper does not recognise is [CaptureNotificationTlsState.DEGRADED],
 * never [CaptureNotificationTlsState.INTERCEPTING]: an unknown state is not a claim
 * that decryption is working. `secretsComplete` is only consulted for a finished run
 * — while a capture is live, accepted-but-not-yet-persisted records are normal and
 * must not read as a failure.
 */
internal object CaptureNotificationPlan {
    fun tlsState(
        enabled: Boolean,
        status: TlsCaptureStatus?,
        secretsComplete: Boolean,
        mitmSuspended: Boolean
    ): CaptureNotificationTlsState = when {
        !enabled -> CaptureNotificationTlsState.NOT_INTERCEPTING
        status == null -> CaptureNotificationTlsState.FAILED
        mitmSuspended || status == TlsCaptureStatus.PAUSED -> CaptureNotificationTlsState.DEGRADED
        status == TlsCaptureStatus.RUNNING || status == TlsCaptureStatus.STARTING ->
            CaptureNotificationTlsState.INTERCEPTING
        status == TlsCaptureStatus.STOPPED ->
            if (secretsComplete) CaptureNotificationTlsState.INTERCEPTING
            else CaptureNotificationTlsState.DEGRADED
        status == TlsCaptureStatus.FAILED || status == TlsCaptureStatus.UNSUPPORTED ->
            CaptureNotificationTlsState.FAILED
        status == TlsCaptureStatus.DISABLED -> CaptureNotificationTlsState.NOT_INTERCEPTING
        else -> CaptureNotificationTlsState.DEGRADED
    }
}

/**
 * The §10.3 rule that a running capture is never reconfigured (TLS-315 step 4).
 *
 * An intercepted TLS connection cannot migrate back to an end-to-end one, so the
 * MVP never tries: the mode belongs to the run that started with it, and a change
 * made while a capture is live is a request for the *next* capture that requires
 * stopping and starting again. The same predicate disables the settings controls
 * and refuses a second start request, so the UI and the service cannot disagree.
 */
internal object TlsModeChangePolicy {
    fun acceptsNewRun(captureRunning: Boolean): Boolean = !captureRunning
}
