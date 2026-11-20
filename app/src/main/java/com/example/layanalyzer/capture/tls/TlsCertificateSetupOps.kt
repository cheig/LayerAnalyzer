// Copyright (c) 2026 cheig
// LayerAnalyzer - https://github.com/cheig/LayerAnalyzer
// Licensed under GNU GPL version 3; see LICENSE.

package com.example.layanalyzer.capture.tls

import java.util.Locale
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext

/**
 * How this Android version can install a user CA (design §7.3.2).
 *
 * The split is by API level, not by a build flag: `KeyChain.createInstallIntent()`
 * can still install a user CA on Android 8–10 (API 26–29), and from Android 11
 * (API 30) on it cannot install a CA at all, so the wizard only guides the user
 * to the system settings. The two branches are both compiled in (minSdk is 26),
 * and [TlsCaInstallPlan] decides between them from the real `SDK_INT`.
 */
internal enum class TlsCaInstallRoute {
    /** API 26–29: the system certificate installer can install a user CA. */
    SystemInstallIntent,

    /** API 30+: no app can install a CA; the user installs it from Settings. */
    SettingsGuidance
}

/**
 * What can honestly be observed after an install attempt.
 *
 * There is deliberately no `INSTALLED`/`TRUSTED` value: a completed system
 * installer is the user finishing a dialog, not a statement that any app trusts
 * the CA (design §7.3.3), and a guidance-only route has no result to observe.
 * [TlsCaInstallObservation.NO_OBSERVABLE_RESULT] is used for that case *and* for
 * the fallback where the platform route exists but no installer resolves it — in
 * both cases the truth is "we do not know", never "installed".
 */
internal enum class TlsCaInstallObservation {
    NOT_ATTEMPTED,
    SYSTEM_DIALOG_COMPLETED,
    SYSTEM_DIALOG_CANCELLED,
    NO_OBSERVABLE_RESULT
}

/**
 * Whether the current test client can reach a controlled HTTPS fixture through
 * the proxy. This card does not build that fixture infra, so the honest value is
 * [NOT_RUN] and the wizard says so instead of claiming a passing test.
 */
internal enum class TlsFixtureTestStatus { NOT_RUN, PASSED, FAILED }

/**
 * Whether a chosen target app was actually observed using the proxy. Nothing in
 * this card observes that, so the honest default is [UNKNOWN].
 */
internal enum class TlsTargetAppStatus { UNKNOWN, CONNECTED, FAILED }

/**
 * The install-intent decision and the meaning of its result (design §7.3.2/§7.3.3).
 * Pure: it takes the API level as a parameter so it can be unit-tested without
 * `android.os.Build`, and it never turns a return value into "installed".
 */
internal object TlsCaInstallPlan {
    /** Android 11 (API 30) is where `createInstallIntent()` stopped installing CAs. */
    const val MAX_SYSTEM_INSTALL_API = 29

    fun routeFor(sdkInt: Int): TlsCaInstallRoute =
        if (sdkInt <= MAX_SYSTEM_INSTALL_API) TlsCaInstallRoute.SystemInstallIntent
        else TlsCaInstallRoute.SettingsGuidance

    /**
     * The only thing a `StartActivityForResult` from the installer can tell us.
     * `RESULT_OK` becomes "the system dialog was completed", never "trusted".
     */
    fun observationForResult(resultOk: Boolean): TlsCaInstallObservation =
        if (resultOk) TlsCaInstallObservation.SYSTEM_DIALOG_COMPLETED
        else TlsCaInstallObservation.SYSTEM_DIALOG_CANCELLED

    fun observationForGuidance(): TlsCaInstallObservation = TlsCaInstallObservation.NO_OBSERVABLE_RESULT
}

/**
 * The `.cer` export plan (design §7.3.1). The wizard exports only the public
 * certificate DER; this object owns the file name and the check that proves the
 * exported bytes carry no private key.
 */
internal object TlsCaExportPlan {
    /**
     * PEM markers plus the bare phrase. The export is DER, so none of these
     * appears in a normal certificate; scanning for them is a refusal-only
     * belt-and-braces check, not something that grants anything.
     */
    private val PRIVATE_KEY_MARKERS = listOf(
        "-----BEGIN PRIVATE KEY-----",
        "-----BEGIN RSA PRIVATE KEY-----",
        "-----BEGIN EC PRIVATE KEY-----",
        "PRIVATE KEY"
    )

    /** Always ends in `.cer`; uses a short, non-sensitive slice of the CA id. */
    fun suggestedFileName(caId: String?): String {
        val hex = caId?.lowercase(Locale.ROOT)?.filter { it in '0'..'9' || it in 'a'..'f' }
        val suffix = hex?.takeIf { it.length >= 8 }?.take(8)
        return if (suffix == null) "layeranalyzer-ca.cer" else "layeranalyzer-ca-$suffix.cer"
    }

    /**
     * The acceptance check that the exported content is a public certificate and
     * not a key. It is exact-byte, case-sensitive ASCII: a DER certificate never
     * contains these sequences, and a PEM-encoded private key always does.
     */
    fun containsPrivateKeyMarker(bytes: ByteArray): Boolean {
        val haystack = bytes
        return PRIVATE_KEY_MARKERS.any { marker -> indexOf(haystack, marker.toByteArray(Charsets.US_ASCII)) >= 0 }
    }

    private fun indexOf(haystack: ByteArray, needle: ByteArray): Int {
        if (needle.isEmpty() || needle.size > haystack.size) return -1
        for (start in 0..haystack.size - needle.size) {
            var match = true
            for (offset in needle.indices) {
                if (haystack[start + offset] != needle[offset]) { match = false; break }
            }
            if (match) return start
        }
        return -1
    }
}

/**
 * The wizard's handle on the CA lifecycle. It adds no semantics of its own: each
 * method is one `TlsCertificateManager` public method, moved off the main thread
 * because every one of them does filesystem, Keystore or native RSA work. `reset`
 * stays refused (`CAPTURE_ACTIVE`) while a capture holds a lease — the wizard
 * cannot bypass the rule that protects a running capture.
 */
internal class TlsCaUiOperations(private val manager: TlsCertificateManager) {
    suspend fun refresh(): TlsCaStatus = withContext(Dispatchers.IO) { manager.status() }

    suspend fun generate(): TlsCaStatus = withContext(Dispatchers.IO) { manager.ensureGenerated() }

    suspend fun export(): TlsCaPublicExport = withContext(Dispatchers.IO) { manager.exportPublicCertificate() }

    suspend fun reset(): TlsCaStatus = withContext(Dispatchers.IO) { manager.reset() }
}
