// Copyright (c) 2026 cheig
// LayerAnalyzer - https://github.com/cheig/LayerAnalyzer
// Licensed under GNU GPL version 3; see LICENSE.

package com.example.layanalyzer.capture.tls

import android.content.Context

/**
 * The one `TlsCertificateManager` for this process (design §7.2, TLS-206/TLS-216).
 *
 * `TlsCertificateManager.activeLeases` is an instance field (TLS-206), so a
 * second instance would let `reset` replace the root while a running capture is
 * still signing leaves with it — exactly the property the CA lifecycle depends
 * on. Every caller that may reset the root therefore goes through this holder:
 * the capture coordinator ([com.example.layanalyzer.capture.LiveCaptureVpnService])
 * and the install wizard (TLS-305) share one manager, one `activeLeases` counter
 * and one published CA.
 *
 * The holder reads, generates and resets nothing by itself; it only answers
 * "which manager". The manager it returns is still responsible for every fixed
 * error code and for refusing `reset` while a lease is open.
 */
internal object TlsCaManagerHolder {
    private val lock = Any()

    @Volatile
    private var instance: TlsCertificateManager? = null

    /** Non-production seam so a test can drive the holder with an injected manager. */
    @Volatile
    private var factory: ((Context) -> TlsCertificateManager)? = null

    /** The process-wide manager, built from [context] on first use. */
    fun get(context: Context): TlsCertificateManager = synchronized(lock) {
        instance ?: (factory?.invoke(context) ?: TlsCertificateManager(context)).also { instance = it }
    }

    /**
     * Test seam only: installs [factory] (or clears it with `null`) and drops the
     * current instance, so a test never touches the app's real published CA.
     * Production code never calls this.
     */
    internal fun installForTest(factory: ((Context) -> TlsCertificateManager)?) {
        synchronized(lock) {
            this.factory = factory
            instance = null
        }
    }
}
