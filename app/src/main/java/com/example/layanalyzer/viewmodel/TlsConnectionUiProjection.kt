// Copyright (c) 2026 cheig
// LayerAnalyzer - https://github.com/cheig/LayerAnalyzer
// Licensed under GNU GPL version 3; see LICENSE.

package com.example.layanalyzer.viewmodel

import com.example.layanalyzer.capture.tls.TlsConnectionSnapshot
import com.example.layanalyzer.data.TlsAssociationReason
import com.example.layanalyzer.data.TlsAssociationState
import com.example.layanalyzer.data.TlsConnectionAssociation
import com.example.layanalyzer.model.TlsCaptureStatus
import com.example.layanalyzer.model.TlsConnectionEvent
import com.example.layanalyzer.model.TlsConnectionPhase
import com.example.layanalyzer.model.TlsErrorCode

/**
 * Whether the capture counts UDP/443 interception at all, and how many such
 * flows are known to be undecrypted.
 *
 * The forwarding-layer rule now exists (TLS-314): the capture's report carries
 * `udpIntervention.blockedDatagrams`, and the default policy still forwards
 * UDP/443 unchanged. That is a datagram count of an intervention read after the
 * run, not a per-connection count of missed decryption a live preview can show,
 * so this reader has no QUIC number and [UNTRACKED] says so instead of printing a
 * zero that would claim "no QUIC was missed". Crucially, a QUIC flow is never
 * folded into the TLS proxy's failure count (design §10.2, card 禁止 5): a
 * forwarded flow is not a failed proxy.
 */
data class TlsQuicSummary(val tracked: Boolean, val undecrypted: Long) {
    companion object {
        /** No live per-connection QUIC count exists yet, so there is no number to show. */
        val UNTRACKED = TlsQuicSummary(tracked = false, undecrypted = 0L)
    }
}

/**
 * One capture's TLS headline numbers for the live preview (design §10.2).
 *
 * The five categories are read from five *separate* counters and are never
 * derived from one another (C03 7, card 口径 1):
 *
 *  * [proxied] — the proxy completed both handshakes;
 *  * [secretsSaved] — the session keys reached the disk and the connection's own
 *    records were complete;
 *  * [decrypted] — Wireshark actually recovered application data;
 *  * [passthrough] — the connection was deliberately forwarded end-to-end;
 *  * [failed] — the interception failed.
 *
 * A proxy success is not a save, and neither is a decryption: [decrypted] stays
 * zero for a live capture, because only the analyser that recovered plaintext may
 * raise it, and the run has not been analysed yet. The UI therefore renders it
 * with [decryptionPendingAnalysis].
 */
data class TlsConnectionSummary(
    val status: TlsCaptureStatus,
    val accepted: Long,
    val proxied: Long,
    val secretsSaved: Long,
    val decrypted: Long,
    /**
     * True when [decrypted] cannot be trusted as an end-to-end decryption count:
     * the summary comes from the live proxy, where a completed handshake proves
     * the proxy worked — not that Wireshark recovered application data (§10.2).
     */
    val decryptionPendingAnalysis: Boolean,
    val passthrough: Long,
    val failed: Long,
    val handshakeFailed: Long,
    val secretsIncomplete: Long,
    val eventsDropped: Long,
    val eventsRejected: Long,
    val eventsNotPersisted: Long,
    val quic: TlsQuicSummary,
    val eventHistoryEvicted: Long = 0,
    /** Null when the engine did not report this reason; not inferred from total bypasses. */
    val handshakeCapacityPassthrough: Long? = null
) {
    /**
     * True when the reader's own counters understate the capture — it fell behind
     * (dropped events) or the journal could not keep up (not persisted). The
     * summary is still truthful, but a reader must say it may be low (TLS-212).
     */
    val countersIncomplete: Boolean
        get() = eventsDropped > 0L || eventsRejected > 0L || eventsNotPersisted > 0L

    companion object {
        /**
         * Projects one store snapshot onto the preview model. The snapshot keeps
         * `decryptedConnections` at zero by construction, so this projection cannot
         * turn a proxy success into a decryption claim.
         */
        fun from(snapshot: TlsConnectionSnapshot): TlsConnectionSummary {
            val stats = snapshot.toCaptureStats()
            val counts = snapshot.counts
            return TlsConnectionSummary(
                status = stats.status,
                accepted = stats.acceptedConnections,
                proxied = stats.proxiedConnections,
                secretsSaved = stats.secretsSavedConnections,
                decrypted = stats.decryptedConnections,
                // Only the analyser raises that count, and this preview is the live
                // proxy's, so the decrypted figure is always "pending analysis".
                decryptionPendingAnalysis = true,
                passthrough = stats.passthroughConnections,
                failed = stats.failedConnections,
                handshakeFailed = counts.handshakeFailed,
                secretsIncomplete = counts.secretsIncomplete,
                eventsDropped = counts.eventsDropped,
                eventsRejected = counts.eventsRejected,
                eventsNotPersisted = counts.eventsNotPersisted,
                eventHistoryEvicted = counts.eventHistoryEvicted,
                handshakeCapacityPassthrough = snapshot.engineDiagnostics?.events?.get("handshakeCapacityPassthrough")
                    ?: snapshot.engineDiagnostics?.budget?.get("refusedHandshakes"),
                quic = TlsQuicSummary.UNTRACKED
            )
        }
    }
}

/** Whether one connection's session keys are usable, partial, or absent. */
enum class TlsConnectionKeyState {
    /** No key material was recorded for this connection. */
    NONE,

    /** The connection's records were complete and at least one reached the disk. */
    SAVED,

    /** Some records were accepted but the connection is not complete. */
    INCOMPLETE
}

/**
 * One connection's link to a real capture frame (TLS-303's correlator output).
 *
 * Only [Matched] carries a frame number, and only [Matched] may enable the frame
 * jump: [Unmatched] and [NotCorrelated] both leave the UI's jump disabled, so no
 * frame number is ever invented for an unassociated event (card 步骤 2).
 */
sealed interface TlsFrameAssociationUi {
    /** A real global frame was confirmed by random, destination and time; the jump is enabled. */
    data class Matched(
        val globalFrameNumber: Long,
        val clientHelloFrames: Int,
        val helloRetryRequest: Boolean
    ) : TlsFrameAssociationUi

    /** The connection is not tied to a frame; [reason] says why and the jump stays disabled. */
    data class Unmatched(val reason: TlsAssociationReason) : TlsFrameAssociationUi

    /**
     * Correlation has not been run for this capture — the production wiring of
     * `TlsConnectionCorrelator` is TLS-310. The jump is disabled because there is
     * nothing to jump to, and the UI says "not available yet" rather than
     * "unmatched", because the two are different facts.
     */
    data object NotCorrelated : TlsFrameAssociationUi
}

/** Fixed, testable explanations; never expose raw socket/platform error text. */
enum class TlsConnectionFailureExplanation {
    DOWNSTREAM_CLOSED, DOWNSTREAM_TIMEOUT, DOWNSTREAM_HANDSHAKE, DOWNSTREAM_ALERT,
    DOWNSTREAM_UNCLASSIFIED, UPSTREAM_CERTIFICATE, SECRETS_INCOMPLETE, CAPTURE_CONTEXT_MISSING,
    CANCELLED
}

/**
 * One connection as the details list renders it. Metadata and fixed codes only —
 * no keylog content, no secret and no plaintext (C03 6).
 */
data class TlsConnectionDetail(
    val connectionId: String,
    val destination: String,
    val wallTimeMillis: Long,
    val sni: String?,
    val downstreamTls: String?,
    val upstreamTls: String?,
    val alpn: String?,
    val phase: TlsConnectionPhase,
    val decisionReason: String?,
    /** The raw structured error code, preserved so the UI never paraphrases it away. */
    val errorCode: TlsErrorCode?,
    val upstreamCertificateSha256: String?,
    val keyState: TlsConnectionKeyState,
    val secretRecordsAccepted: Long,
    val secretRecordsPersisted: Long,
    val frame: TlsFrameAssociationUi
) {
    /** Reason-aware explanation; a legacy rejection code alone proves no trust decision. */
    val failureExplanation: TlsConnectionFailureExplanation?
        get() = when (errorCode) {
            TlsErrorCode.CANCELLED -> TlsConnectionFailureExplanation.CANCELLED
            TlsErrorCode.UPSTREAM_CERT_INVALID -> TlsConnectionFailureExplanation.UPSTREAM_CERTIFICATE
            TlsErrorCode.SECRETS_INCOMPLETE -> TlsConnectionFailureExplanation.SECRETS_INCOMPLETE
            TlsErrorCode.CAPTURE_CONTEXT_MISSING -> TlsConnectionFailureExplanation.CAPTURE_CONTEXT_MISSING
            TlsErrorCode.IO_ERROR, TlsErrorCode.DOWNSTREAM_TLS_REJECTED -> when (decisionReason) {
                "downstream_connection_closed" -> TlsConnectionFailureExplanation.DOWNSTREAM_CLOSED
                "downstream_handshake_timeout" -> TlsConnectionFailureExplanation.DOWNSTREAM_TIMEOUT
                "downstream_handshake_failed" -> TlsConnectionFailureExplanation.DOWNSTREAM_HANDSHAKE
                "downstream_tls_alert" -> TlsConnectionFailureExplanation.DOWNSTREAM_ALERT
                else -> if (errorCode == TlsErrorCode.DOWNSTREAM_TLS_REJECTED) {
                    // Legacy engines also used this code for EOF/reset: no trust verdict.
                    TlsConnectionFailureExplanation.DOWNSTREAM_UNCLASSIFIED
                } else null
            }
            else -> null
        }

    /** The jump is enabled only for a real, matched capture frame. */
    val jumpableFrame: Long?
        get() = (frame as? TlsFrameAssociationUi.Matched)?.globalFrameNumber

    /**
     * True when the upstream certificate was verified. The event carries a
     * fingerprint only after the platform verifier accepted the chain (§6.4), so a
     * present fingerprint is the verified case and an absent one is "not recorded"
     * — never the reverse.
     */
    val upstreamCertificateVerified: Boolean
        get() = !upstreamCertificateSha256.isNullOrEmpty()
}

/**
 * The pure projection from a store snapshot to the preview's UI models. It reads
 * no clock, no disk and no Compose state, so it runs as a plain host-JVM function
 * (TLS-306's `J` case) and can never be the reason a byte triggers a repaint.
 */
object TlsConnectionUiProjection {

    fun summary(snapshot: TlsConnectionSnapshot): TlsConnectionSummary = TlsConnectionSummary.from(snapshot)

    /**
     * One detail per retained connection, most recently updated first — the
     * snapshot's own order. [associations] is optional on purpose: the production
     * correlator is wired by TLS-310, so today it is empty and every connection
     * reports [TlsFrameAssociationUi.NotCorrelated] with the jump disabled.
     */
    fun details(
        snapshot: TlsConnectionSnapshot,
        associations: List<TlsConnectionAssociation> = emptyList()
    ): List<TlsConnectionDetail> {
        val byConnection = associations.associateBy { it.connectionId }
        return snapshot.connections.map { event -> detail(event, byConnection[event.connectionId]) }
    }

    private fun detail(event: TlsConnectionEvent, association: TlsConnectionAssociation?): TlsConnectionDetail =
        TlsConnectionDetail(
            connectionId = event.connectionId,
            destination = "${event.destinationIp}:${event.destinationPort}",
            wallTimeMillis = event.wallTimeMillis,
            sni = event.sni,
            downstreamTls = event.downstreamTls,
            upstreamTls = event.upstreamTls,
            alpn = event.alpn,
            phase = event.phase,
            decisionReason = event.decisionReason,
            errorCode = event.error?.code,
            upstreamCertificateSha256 = event.upstreamCertificateSha256,
            keyState = keyState(event),
            secretRecordsAccepted = event.secretRecordsAccepted,
            secretRecordsPersisted = event.secretRecordsPersisted,
            frame = frameAssociation(association)
        )

    /**
     * Keys are "saved" only when the connection's own records were complete *and*
     * something reached the disk. A connection with accepted-but-unpersisted
     * records is [TlsConnectionKeyState.INCOMPLETE], never "saved" — accepted is
     * not persisted (C05).
     */
    private fun keyState(event: TlsConnectionEvent): TlsConnectionKeyState = when {
        event.secretsComplete && event.secretRecordsPersisted > 0L -> TlsConnectionKeyState.SAVED
        event.secretRecordsPersisted > 0L || event.secretRecordsAccepted > 0L -> TlsConnectionKeyState.INCOMPLETE
        else -> TlsConnectionKeyState.NONE
    }

    /**
     * A frame number is exposed only for a genuinely [TlsAssociationState.MATCHED]
     * association with a non-null frame. Every other state — including a
     * [TlsAssociationState.MATCHED] that somehow lacked a frame — falls back to
     * [TlsFrameAssociationUi.Unmatched], so the jump can never be enabled without a
     * real frame.
     */
    private fun frameAssociation(association: TlsConnectionAssociation?): TlsFrameAssociationUi {
        if (association == null) return TlsFrameAssociationUi.NotCorrelated
        val frame = association.globalFrameNumber
        return if (association.state == TlsAssociationState.MATCHED && frame != null) {
            TlsFrameAssociationUi.Matched(
                globalFrameNumber = frame,
                clientHelloFrames = association.clientHelloFrames,
                helloRetryRequest = association.helloRetryRequest
            )
        } else {
            TlsFrameAssociationUi.Unmatched(association.reason)
        }
    }
}
