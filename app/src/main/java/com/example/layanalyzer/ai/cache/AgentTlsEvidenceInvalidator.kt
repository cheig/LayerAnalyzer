// Copyright (c) 2026 cheig
// LayerAnalyzer - https://github.com/cheig/LayerAnalyzer
// Licensed under GNU GPL version 3; see LICENSE.

package com.example.layanalyzer.ai.cache

import com.example.layanalyzer.data.AgentSessionStore
import com.example.layanalyzer.data.CaptureCleanupEvent

/**
 * TLS-313: the host-side consumer of TLS-312's capture-cleanup journal.
 *
 * Design §11.2 requires that deleting a capture also drops the sensitive
 * derived content: the deterministic tool cache and the saved Agent
 * conversations both key their entries by the capture's content fingerprint,
 * so a deleted capture must leave nothing behind that a later run could serve
 * or the user could reopen.  TLS-312 already clears workspaces, bookmarks and
 * recents; this class closes the AI half of the same boundary.
 *
 * It never reads decrypted content and never touches a PCAP, a keylog or a
 * secret — it only drops records.  Every method is idempotent, so replaying
 * the durable journal on each launch is safe even when a previous replay
 * already removed the entries.
 */
class AgentTlsEvidenceInvalidator(
    private val toolCache: AgentToolCache? = null,
    private val sessionStore: AgentSessionStore? = null
) {

    /**
     * Drop every AI artefact keyed by one capture fingerprint.
     *
     * Returns how many saved conversations were removed; the tool cache reports
     * its own counts through [AgentToolCache.stats].
     */
    fun invalidateFingerprint(fingerprint: String): Int {
        if (fingerprint.isBlank()) return 0
        toolCache?.invalidateCapture(fingerprint)
        val store = sessionStore ?: return 0
        var removed = 0
        // listForCapture returns a snapshot, so deleting inside the loop cannot
        // change what is being iterated.
        store.listForCapture(fingerprint).forEach { summary ->
            if (store.delete(summary.conversationId)) removed += 1
        }
        return removed
    }

    /** Apply one durable cleanup event (TLS-312's `CaptureCleanupEvent`). */
    fun onCaptureCleanup(event: CaptureCleanupEvent): Int =
        event.captureFingerprints.fold(0) { total, fingerprint ->
            total + invalidateFingerprint(fingerprint)
        }

    /** Replay the durable cleanup journal at startup, idempotently. */
    fun replay(events: List<CaptureCleanupEvent>): Int =
        events.fold(0) { total, event -> total + onCaptureCleanup(event) }
}
