// Copyright (c) 2026 cheig
// LayerAnalyzer - https://github.com/cheig/LayerAnalyzer
// Licensed under GNU GPL version 3; see LICENSE.

package com.example.layanalyzer.data

import com.example.layanalyzer.model.TlsConnectionEvent
import java.util.Locale

/**
 * One ClientHello the analyser actually found in the capture (native projection, TLS-303).
 *
 * Every field is a real observation from dissecting the capture's ClientHello frames, not
 * a guess: [clientRandom] is the 32-byte `tls.handshake.random` as lowercase hex,
 * [destinationIp]/[destinationPort] are the frame's network destination, and
 * [frameTimeMillis] is the frame's absolute (epoch) timestamp. [frameNumber] is the 1-based
 * position in the analysis file the projection dissected; the correlator maps it to the
 * user's global frame number through [TlsFrameMapping]. No key material is carried here.
 */
data class ClientHelloObservation(
    val frameNumber: Long,
    val frameTimeMillis: Long,
    val clientRandom: String,
    val destinationIp: String,
    val destinationPort: Int
)

/**
 * TLS-302's frame identity: an analysis-file position back to the user's 1-based global
 * frame number. [globalFrameNumber] returns null when the frame is not part of the merged
 * capture (a missing segment or an incomplete context), so no invented frame number can
 * ever be produced for a frame the merge did not actually include.
 */
fun interface TlsFrameMapping {
    fun globalFrameNumber(analysisFrame: Long): Long?

    companion object {
        /**
         * A mapping for one [CaptureAnalysisSource]: a merged capture maps through
         * [CaptureAnalysisSource.Merged.locateMerged]; a legacy single file is already in
         * the user's numbering (1:1); a missing/refused/cancelled source has no frames at all.
         */
        fun of(source: CaptureAnalysisSource): TlsFrameMapping? = when (source) {
            is CaptureAnalysisSource.Merged -> TlsFrameMapping { merged ->
                source.locateMerged(merged)?.globalFrame
            }
            is CaptureAnalysisSource.Legacy -> TlsFrameMapping { frame -> frame.takeIf { it >= 1L } }
            is CaptureAnalysisSource.Missing,
            is CaptureAnalysisSource.Refused,
            is CaptureAnalysisSource.Cancelled -> null
        }
    }
}

/** The honest outcome of correlating one connection with the capture (design §8.4). */
enum class TlsAssociationState { MATCHED, UNMATCHED, AMBIGUOUS }

/** Why a connection is, or is not, tied to a capture frame. Never a disguised success. */
enum class TlsAssociationReason {
    /** A real ClientHello frame was found and confirmed by random, destination and time. */
    MATCHED,
    /** The connection never reported a downstream client_random, so it cannot be matched. */
    NO_CLIENT_RANDOM,
    /** No ClientHello with that random is present (a missing handshake, e.g. an unmerged segment). */
    NO_CLIENT_HELLO,
    /** The random was seen, but not towards this connection's destination. */
    DESTINATION_MISMATCH,
    /** The random and destination matched, but the capture frame is outside the time window. */
    TIME_MISMATCH,
    /** The same random was seen towards more than one destination: genuinely ambiguous. */
    MULTIPLE_DESTINATIONS,
    /** The matching frame is outside the merged capture, so it has no global frame number. */
    FRAME_NOT_IN_CAPTURE,
    /** There is no analysis source to map frames with (missing/refused/cancelled capture). */
    NO_FRAME_MAPPING
}

/**
 * One connection's association with the capture (design §8.4).
 *
 * [globalFrameNumber] is the user's 1-based global frame number of the ClientHello, and is
 * null for [TlsAssociationState.UNMATCHED]/[TlsAssociationState.AMBIGUOUS]: an unassociated
 * event never carries a fabricated frame number.
 *
 * [originalApplicationKnown] is always false: the SOCKS hop's loopback source port is not
 * the original app's five-tuple, so no app/UID attribution is implied (§8.4, card 禁止).
 */
data class TlsConnectionAssociation(
    val captureId: String,
    val connectionId: String,
    val state: TlsAssociationState,
    val reason: TlsAssociationReason,
    val destinationIp: String,
    val destinationPort: Int,
    val clientRandom: String?,
    val globalFrameNumber: Long?,
    /** How many ClientHello frames share this client_random; > 1 means an HRR or a retransmission. */
    val clientHelloFrames: Int,
    val helloRetryRequest: Boolean,
    val originalApplicationKnown: Boolean = false
)

/**
 * Ties proxy connection events to the real capture frames that carry their handshake
 * (design §8.4).
 *
 * The key is the parsed downstream `client_random` plus the capture: an IP or an SNI alone
 * never merges two connections, which is exactly what keeps simultaneous TLS connections to
 * the same destination from cross-wiring. A candidate is then confirmed by destination
 * address and by a time window, because a random is a strong key but not a proof on its own.
 *
 * The rule for a repeated ClientHello is explicit. TLS 1.3 HelloRetryRequest makes the
 * client send two ClientHellos that share one client_random (RFC 8446); a TCP retransmission
 * of a ClientHello does the same. In both cases there is still one connection, so the frames
 * are folded into one [TlsConnectionAssociation] with [TlsConnectionAssociation.helloRetryRequest]
 * set — never two connections and never [TlsAssociationState.AMBIGUOUS]. The reported frame is
 * the earliest such ClientHello, the one that opens the handshake.
 *
 * The correlator is a pure function over its inputs so it is fully testable with fakes; it
 * never reads the clock, the disk or native state.
 */
class TlsConnectionCorrelator(
    private val captureId: String,
    private val timeWindowMillis: Long = DEFAULT_TIME_WINDOW_MILLIS
) {
    init {
        require(timeWindowMillis > 0L) { "time window must be positive" }
    }

    /**
     * One association per connection found in [events], in first-seen order.
     *
     * [events] may contain several events per connection (the caller supplies the window or
     * the reloaded history); they are grouped by connection, and the connection's earliest
     * timestamp and first reported client_random are used. Events for another capture are
     * ignored. [frameMapping] may be null when there is no analysis source; then no connection
     * can be matched.
     */
    fun associate(
        events: List<TlsConnectionEvent>,
        observations: List<ClientHelloObservation>,
        frameMapping: TlsFrameMapping?
    ): List<TlsConnectionAssociation> {
        val normalized = observations.map { observation ->
            observation.copy(clientRandom = normalizeClientRandom(observation.clientRandom))
        }
        return events.filter { it.captureId == captureId }
            .groupBy { it.connectionId }
            .map { (connectionId, group) -> associateOne(connectionId, group, normalized, frameMapping) }
    }

    private fun associateOne(
        connectionId: String,
        group: List<TlsConnectionEvent>,
        observations: List<ClientHelloObservation>,
        frameMapping: TlsFrameMapping?
    ): TlsConnectionAssociation {
        // The connection's identity for matching: its earliest event (closest to the
        // ClientHello in time) and the first client_random it ever reported.
        val earliest = group.minWith(compareBy({ it.wallTimeMillis }, { it.eventSequence }))
        val clientRandom = group.firstNotNullOfOrNull { event ->
            event.downstreamClientRandom?.let { normalizeClientRandom(it) }?.takeIf { it.isNotEmpty() }
        }
        fun result(
            state: TlsAssociationState,
            reason: TlsAssociationReason,
            frame: Long? = null,
            frames: Int = 0,
            helloRetry: Boolean = false
        ) = TlsConnectionAssociation(
            captureId = captureId,
            connectionId = connectionId,
            state = state,
            reason = reason,
            destinationIp = earliest.destinationIp,
            destinationPort = earliest.destinationPort,
            clientRandom = clientRandom,
            globalFrameNumber = frame,
            clientHelloFrames = frames,
            helloRetryRequest = helloRetry
        )

        if (clientRandom.isNullOrEmpty()) return result(TlsAssociationState.UNMATCHED, TlsAssociationReason.NO_CLIENT_RANDOM)

        val byRandom = observations.filter { it.clientRandom == clientRandom }
        if (byRandom.isEmpty()) return result(TlsAssociationState.UNMATCHED, TlsAssociationReason.NO_CLIENT_HELLO)

        // The random alone does not separate two destinations: that is the one genuine
        // ambiguity, and it must not be resolved by picking a frame.
        if (byRandom.map { it.destinationIp }.distinct().size > 1) {
            return result(TlsAssociationState.AMBIGUOUS, TlsAssociationReason.MULTIPLE_DESTINATIONS)
        }

        val byDestination = byRandom.filter {
            it.destinationIp == earliest.destinationIp && it.destinationPort == earliest.destinationPort
        }
        if (byDestination.isEmpty()) return result(TlsAssociationState.UNMATCHED, TlsAssociationReason.DESTINATION_MISMATCH)

        val byTime = byDestination.filter {
            kotlin.math.abs(it.frameTimeMillis - earliest.wallTimeMillis) <= timeWindowMillis
        }
        if (byTime.isEmpty()) return result(TlsAssociationState.UNMATCHED, TlsAssociationReason.TIME_MISMATCH)

        if (frameMapping == null) return result(TlsAssociationState.UNMATCHED, TlsAssociationReason.NO_FRAME_MAPPING)

        val globalFrames = byTime.mapNotNull { frameMapping.globalFrameNumber(it.frameNumber) }.distinct().sorted()
        if (globalFrames.isEmpty()) return result(TlsAssociationState.UNMATCHED, TlsAssociationReason.FRAME_NOT_IN_CAPTURE)

        // One connection, however many ClientHellos share its random (HRR or retransmission).
        return result(
            state = TlsAssociationState.MATCHED,
            reason = TlsAssociationReason.MATCHED,
            frame = globalFrames.first(),
            frames = globalFrames.size,
            helloRetry = globalFrames.size > 1
        )
    }

    companion object {
        /**
         * Confirmation window for the destination/time check. The proxy event's wall clock and
         * the capture frame's absolute timestamp are the same device's clock, and a ClientHello
         * is sent within moments of the proxy accepting the connection; 60 s is wide enough for
         * clock jitter and narrow enough not to absorb an unrelated connection.
         */
        const val DEFAULT_TIME_WINDOW_MILLIS = 60_000L

        /** Lowercase hex without separators, so an engine and a dissector value compare equal. */
        internal fun normalizeClientRandom(value: String): String =
            value.filter { !it.isWhitespace() && it != ':' }.lowercase(Locale.ROOT)
    }
}
