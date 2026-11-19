// Copyright (c) 2026 cheig
// LayerAnalyzer - https://github.com/cheig/LayerAnalyzer
// Licensed under GNU GPL version 3; see LICENSE.

package com.example.layanalyzer.capture.tls

import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow

/**
 * The in-process hand-off between the capture service and the UI for the live TLS
 * summary (TLS-306).
 *
 * It mirrors the existing [com.example.layanalyzer.capture.LiveCaptureStore]
 * pattern — one process-wide holder with a [StateFlow] — rather than introducing a
 * second architecture: the service writes here from its capture loop, the
 * ViewModel collects, and the capture UI reads the latest value.
 *
 * The publication rate is not decided here. [publishIfDue] delegates to the
 * store's own C10 gate ([TlsConnectionStore.dueForPublish], 250 ms), which is the
 * single throttle the task asks for: a caller may invoke it as often as it likes —
 * once per received byte even — and only the first call in each interval reaches
 * the [StateFlow], so Compose never repaints per byte.
 */
object TlsConnectionPreviewStore {

    private val _snapshot = MutableStateFlow<TlsConnectionSnapshot?>(null)

    /** The most recently published summary, or null when no capture is/was intercepting. */
    val snapshot: StateFlow<TlsConnectionSnapshot?> = _snapshot.asStateFlow()

    /** Publishes [snapshot] unconditionally. Reserved for a state transition such as the final stop. */
    fun publish(snapshot: TlsConnectionSnapshot) {
        _snapshot.value = snapshot
    }

    /** Drops the previous capture's summary so a new run never shows stale counts. */
    fun clear() {
        _snapshot.value = null
    }

    /**
     * Publishes [store]'s snapshot only when the store's own gate allows it, and
     * returns whether it did. The gate is [TlsConnectionStore.dueForPublish] — C10's
     * fastest refresh — so this is at most one publication per 250 ms.
     */
    fun publishIfDue(store: TlsConnectionStore): Boolean {
        if (!store.dueForPublish()) return false
        publish(store.snapshot())
        return true
    }
}
