// Copyright (c) 2026 cheig
// LayerAnalyzer - https://github.com/cheig/LayerAnalyzer
// Licensed under GNU GPL version 3; see LICENSE.

package com.example.layanalyzer.ai.privacy

import com.example.layanalyzer.data.TlsAssociationState
import com.example.layanalyzer.data.TlsConnectionAssociation
import com.example.layanalyzer.model.AgentJsonObject
import com.example.layanalyzer.model.TlsConnectionEvent

/**
 * One active-proxy observation projected for an Agent (TLS-313, design §11.3).
 *
 * A proxy handshake observation describes something the app observed on its own
 * leg between the app and the local proxy — an accepted connection, an upstream
 * handshake, a chosen ALPN, a failure code.  It is **not** a TUN frame, and it
 * must never be presented to a model as one.  [globalFrameNumber] is therefore
 * null unless a downstream ClientHello was genuinely correlated to a real frame
 * by [com.example.layanalyzer.data.TlsConnectionCorrelator]; an upstream-only
 * observation has no frame at all and this type gives it none.
 */
data class AgentProxyObservation(
    val source: String,
    val captureId: String,
    val connectionId: String,
    val eventSequence: Long,
    val phase: String,
    val destinationIp: String,
    val destinationPort: Int,
    val upstreamTls: String? = null,
    val alpn: String? = null,
    val errorCode: String? = null,
    /** The real ClientHello frame, or null. Never invented for a proxy event. */
    val globalFrameNumber: Long? = null
) {
    fun toAgentJson(): AgentJsonObject = buildMap {
        put(AgentDecryptedContentPolicy.DATA_SOURCE_KEY, source)
        put("captureId", captureId)
        put("connectionId", connectionId)
        put("eventSequence", eventSequence)
        put("phase", phase)
        put("destinationIp", destinationIp)
        put("destinationPort", destinationPort)
        put("upstreamTls", upstreamTls)
        put("alpn", alpn)
        put("errorCode", errorCode)
        put("globalFrameNumber", globalFrameNumber)
        // Explicit, so a model cannot read a missing frame as "frame zero" and
        // cannot mistake a proxy observation for a capture frame.
        put("frameNumberKnown", globalFrameNumber != null)
    }
}

/**
 * The labelling and frame-honesty rules for active-proxy evidence.
 *
 * Design §11.3: handshake observations made on the app-to-proxy leg are labelled
 * [SOURCE] and referenced separately from TUN frame evidence.  The only frame
 * number this module will ever emit is the one a matched downstream ClientHello
 * already carries; everything else is null.
 */
object AgentTlsEvidence {

    /** The evidence/source label for active-proxy observations. */
    const val SOURCE = AgentDecryptedContentPolicy.APP_TO_PROXY_SOURCE

    /** Whether a tool-marked data source names an active-proxy observation. */
    fun isProxyObservation(source: Any?): Boolean =
        (source as? String)?.trim()?.lowercase(java.util.Locale.US) == SOURCE

    /**
     * The real capture frame a proxy connection may cite, or null.
     *
     * Only [TlsAssociationState.MATCHED] carries a frame, and even then the
     * correlator leaves [TlsConnectionAssociation.globalFrameNumber] null when
     * the ClientHello fell outside the merged capture.  An UNMATCHED or
     * AMBIGUOUS connection — and any upstream-only event — yields null, so no
     * proxy observation can ever be presented with a fabricated frame number.
     */
    fun frameNumberFor(association: TlsConnectionAssociation?): Long? =
        association
            ?.takeIf { it.state == TlsAssociationState.MATCHED }
            ?.globalFrameNumber

    /** Project one connection event, using [association] only for its frame. */
    fun fromEvent(
        event: TlsConnectionEvent,
        association: TlsConnectionAssociation? = null
    ): AgentProxyObservation = AgentProxyObservation(
        source = SOURCE,
        captureId = event.captureId,
        connectionId = event.connectionId,
        eventSequence = event.eventSequence,
        phase = event.phase.wireName,
        destinationIp = event.destinationIp,
        destinationPort = event.destinationPort,
        upstreamTls = event.upstreamTls,
        alpn = event.alpn,
        errorCode = event.error?.code?.name,
        globalFrameNumber = frameNumberFor(association)
    )
}
