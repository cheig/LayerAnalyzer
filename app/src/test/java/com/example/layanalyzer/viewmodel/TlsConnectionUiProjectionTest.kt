// Copyright (c) 2026 cheig
// LayerAnalyzer - https://github.com/cheig/LayerAnalyzer
// Licensed under GNU GPL version 3; see LICENSE.

package com.example.layanalyzer.viewmodel

import com.example.layanalyzer.capture.tls.TlsConnectionPreviewStore
import com.example.layanalyzer.capture.tls.TlsConnectionStore
import com.example.layanalyzer.capture.tls.TlsConnectionStoreLimits
import com.example.layanalyzer.data.TlsAssociationReason
import com.example.layanalyzer.data.TlsAssociationState
import com.example.layanalyzer.data.TlsConnectionAssociation
import com.example.layanalyzer.model.TlsConnectionEvent
import com.example.layanalyzer.model.TlsConnectionPhase
import com.example.layanalyzer.model.TlsError
import com.example.layanalyzer.model.TlsErrorCode
import java.util.concurrent.atomic.AtomicLong
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * Host-JVM tests for the TLS preview projection (TLS-306).
 *
 * They run without a device, `android.util.Log` or the Compose runtime: the code
 * under test is a pure function over a [com.example.layanalyzer.capture.tls.TlsConnectionSnapshot],
 * and the publication gate is the connection store's own clock-injected method.
 *
 * The behaviours asserted here are the card's acceptance case 1:
 * out-of-order/duplicate/dropped events leave the latest summary correct, and a
 * connection without saved secrets is never reported as decryptable.
 */
class TlsConnectionUiProjectionTest {

    private fun event(
        sequence: Long,
        connectionId: String,
        phase: TlsConnectionPhase,
        destinationIp: String = "203.0.113.10",
        destinationPort: Int = 443,
        error: TlsErrorCode? = null,
        secretsComplete: Boolean = false,
        accepted: Long = 0L,
        persisted: Long = 0L,
        clientRandom: String? = null
    ): TlsConnectionEvent = TlsConnectionEvent(
        captureId = CAPTURE,
        connectionId = connectionId,
        eventSequence = sequence,
        monotonicNanos = sequence * 1_000_000L,
        wallTimeMillis = BASE_WALL_MILLIS + sequence,
        destinationIp = destinationIp,
        destinationPort = destinationPort,
        networkGeneration = 1L,
        phase = phase,
        downstreamClientRandom = clientRandom,
        error = error?.let { TlsError(it) },
        secretRecordsAccepted = accepted,
        secretRecordsPersisted = persisted,
        secretsComplete = secretsComplete
    )

    private fun store(
        limits: TlsConnectionStoreLimits = TlsConnectionStoreLimits(),
        nanoTime: () -> Long = System::nanoTime
    ) = TlsConnectionStore(CAPTURE, limits, nanoTime)

    @Test
    fun outOfOrderAndDuplicateEventsLeaveTheLatestSummaryCorrect() {
        val store = store()
        // Connection a: a relay event arrives before its accept, then a terminal
        // event that is delivered twice. Only the first delivery may count.
        assertTrue(store.append(event(2L, "a", TlsConnectionPhase.RELAYING)))
        assertFalse("a stale sequence is refused", store.append(event(1L, "a", TlsConnectionPhase.ACCEPTED)))
        assertTrue(store.append(event(3L, "a", TlsConnectionPhase.CLOSED, secretsComplete = true, accepted = 4L, persisted = 4L)))
        assertFalse(
            "a duplicate terminal event is refused",
            store.append(event(3L, "a", TlsConnectionPhase.CLOSED, secretsComplete = true, accepted = 4L, persisted = 4L))
        )
        // Connection b: accept, then a downstream rejection; an out-of-order accept is refused.
        assertTrue(store.append(event(4L, "b", TlsConnectionPhase.ACCEPTED)))
        assertFalse("an older sequence is refused", store.append(event(1L, "b", TlsConnectionPhase.ACCEPTED)))
        assertTrue(
            store.append(
                event(5L, "b", TlsConnectionPhase.FAILED, error = TlsErrorCode.DOWNSTREAM_TLS_REJECTED)
            )
        )

        val summary = TlsConnectionUiProjection.summary(store.snapshot())
        assertEquals(2L, summary.accepted)
        assertEquals(1L, summary.proxied)
        assertEquals(1L, summary.secretsSaved)
        assertEquals(0L, summary.decrypted)
        assertEquals(0L, summary.passthrough)
        assertEquals(1L, summary.failed)
        assertEquals(1L, summary.handshakeFailed)
        assertEquals(0L, summary.secretsIncomplete)
        assertEquals(3L, summary.eventsRejected)
        assertTrue("refused events are reflected honestly", summary.countersIncomplete)

        // Two connections were retained, most recently updated first.
        val details = TlsConnectionUiProjection.details(store.snapshot())
        assertEquals(2, details.size)
        val rejected = details.single { it.connectionId == "b" }
        assertEquals(TlsErrorCode.DOWNSTREAM_TLS_REJECTED, rejected.errorCode)
    }

    @Test
    fun aConnectionWithoutSavedSecretsIsNeverReportedAsDecryptable() {
        val store = store()
        // A proxied connection whose secrets never reached the disk: the handshake
        // succeeded, the keys did not. It must not look decryptable.
        assertTrue(store.append(event(1L, "a", TlsConnectionPhase.RELAYING)))
        assertTrue(store.append(event(2L, "a", TlsConnectionPhase.CLOSED)))

        val summary = TlsConnectionUiProjection.summary(store.snapshot())
        assertEquals(1L, summary.proxied)
        assertEquals(0L, summary.secretsSaved)
        assertEquals("a proxy success is not a decryption", 0L, summary.decrypted)
        assertTrue(summary.decryptionPendingAnalysis)

        val detail = TlsConnectionUiProjection.details(store.snapshot()).single()
        assertEquals(TlsConnectionKeyState.NONE, detail.keyState)
        assertNull(detail.jumpableFrame)
    }

    @Test
    fun proxiedWithAcceptedButUnpersistedSecretsIsNotCountedAsSaved() {
        val store = store()
        assertTrue(store.append(event(1L, "a", TlsConnectionPhase.RELAYING)))
        // Accepted records exist, but the connection is not complete: accepted is
        // not persisted (C05), so it is neither "saved" nor decryptable.
        assertTrue(
            store.append(
                event(2L, "a", TlsConnectionPhase.CLOSED, secretsComplete = false, accepted = 3L, persisted = 2L)
            )
        )

        val summary = TlsConnectionUiProjection.summary(store.snapshot())
        assertEquals(1L, summary.proxied)
        assertEquals(0L, summary.secretsSaved)
        assertEquals(1L, summary.secretsIncomplete)
        assertEquals(0L, summary.decrypted)

        val detail = TlsConnectionUiProjection.details(store.snapshot()).single()
        assertEquals(TlsConnectionKeyState.INCOMPLETE, detail.keyState)
    }

    @Test
    fun retiredHistoryDoesNotMakeCompleteCountersLookIncomplete() {
        // A two-event window: ten events for one connection overflow it, and the
        // store reports the drop instead of silently losing it.
        val store = store(TlsConnectionStoreLimits(maxEvents = 2))
        assertTrue(store.append(event(1L, "a", TlsConnectionPhase.ACCEPTED)))
        assertTrue(store.append(event(2L, "a", TlsConnectionPhase.RELAYING)))
        for (sequence in 3L..10L) {
            store.append(event(sequence, "a", TlsConnectionPhase.RELAYING))
        }

        val summary = TlsConnectionUiProjection.summary(store.snapshot())
        assertEquals("the relay phase is counted once, however many events", 1L, summary.proxied)
        assertEquals(8L, summary.eventHistoryEvicted)
        assertEquals(0L, summary.eventsDropped)
        assertFalse(summary.countersIncomplete)

        // The connection's retained state survives the window overflow.
        val detail = TlsConnectionUiProjection.details(store.snapshot()).single()
        assertEquals(TlsConnectionPhase.RELAYING, detail.phase)
    }

    @Test
    fun handshakeCapacityBypassesAreReadFromTheirOwnEngineCounter() {
        val store = store()
        assertNull(TlsConnectionUiProjection.summary(store.snapshot()).handshakeCapacityPassthrough)
        assertTrue(store.recordEngineStats("""{"success":true,"events":{"bytesToUpstream":0,"bytesToDownstream":0,"eventsDropped":0,"handshakeCapacityPassthrough":7}}"""))
        val summary = TlsConnectionUiProjection.summary(store.snapshot())
        assertEquals(7L, summary.handshakeCapacityPassthrough)
        assertEquals(0L, summary.failed)
        assertEquals(0L, summary.decrypted)
    }

    @Test
    fun downstreamExplanationsDistinguishAlertsFromClosureAndLegacyAmbiguity() {
        val cases = listOf(
            Triple(TlsErrorCode.IO_ERROR, "downstream_connection_closed", TlsConnectionFailureExplanation.DOWNSTREAM_CLOSED),
            Triple(TlsErrorCode.IO_ERROR, "downstream_handshake_timeout", TlsConnectionFailureExplanation.DOWNSTREAM_TIMEOUT),
            Triple(TlsErrorCode.IO_ERROR, "downstream_handshake_failed", TlsConnectionFailureExplanation.DOWNSTREAM_HANDSHAKE),
            Triple(TlsErrorCode.DOWNSTREAM_TLS_REJECTED, "downstream_tls_alert", TlsConnectionFailureExplanation.DOWNSTREAM_ALERT),
            // Older engines labelled timeout/EOF as rejection; never infer trust from it.
            Triple(TlsErrorCode.DOWNSTREAM_TLS_REJECTED, "downstream_handshake_timeout", TlsConnectionFailureExplanation.DOWNSTREAM_TIMEOUT),
            Triple(TlsErrorCode.DOWNSTREAM_TLS_REJECTED, "downstream_handshake_rejected", TlsConnectionFailureExplanation.DOWNSTREAM_UNCLASSIFIED),
            Triple(TlsErrorCode.DOWNSTREAM_TLS_REJECTED, null, TlsConnectionFailureExplanation.DOWNSTREAM_UNCLASSIFIED),
            Triple(TlsErrorCode.CANCELLED, "handshake_cancelled", TlsConnectionFailureExplanation.CANCELLED),
            Triple(TlsErrorCode.SECRETS_INCOMPLETE, "downstream_key_log_failed", TlsConnectionFailureExplanation.SECRETS_INCOMPLETE),
            Triple(TlsErrorCode.UPSTREAM_CERT_INVALID, "upstream_verification_failed", TlsConnectionFailureExplanation.UPSTREAM_CERTIFICATE),
            Triple(TlsErrorCode.IO_ERROR, "upstream_handshake_failed", null)
        )
        for ((code, reason, expected) in cases) {
            val store = store()
            val failure = event(1L, "a", TlsConnectionPhase.FAILED, error = code).copy(decisionReason = reason)
            assertTrue(store.append(failure))
            val detail = TlsConnectionUiProjection.details(store.snapshot()).single()
            assertEquals("$code / $reason", expected, detail.failureExplanation)
            assertEquals(code, detail.errorCode)
            assertEquals(reason, detail.decisionReason)
            assertEquals(1L, store.snapshot().counts.failed)
            assertEquals(0L, TlsConnectionUiProjection.summary(store.snapshot()).decrypted)
        }
    }

    @Test
    fun quicIsNeverCountedAsAFailedTlsProxy() {
        val store = store()
        assertTrue(
            store.append(event(1L, "a", TlsConnectionPhase.FAILED, error = TlsErrorCode.UPSTREAM_CERT_INVALID))
        )

        val summary = TlsConnectionUiProjection.summary(store.snapshot())
        // The only failure is the genuine TLS one; QUIC is not tracked and adds
        // nothing to the failure count.
        assertEquals(1L, summary.failed)
        assertFalse(summary.quic.tracked)
        assertEquals(0L, summary.quic.undecrypted)
    }

    @Test
    fun matchedAssociationEnablesTheJumpAndEveryOtherStateDisablesIt() {
        val store = store()
        assertTrue(store.append(event(1L, "a", TlsConnectionPhase.CLOSED, clientRandom = CLIENT_RANDOM)))
        val snapshot = store.snapshot()

        val matched = TlsConnectionUiProjection.details(
            snapshot,
            associations = listOf(association(TlsAssociationState.MATCHED, TlsAssociationReason.MATCHED, frame = 1007L))
        ).single()
        val matchedFrame = matched.frame as TlsFrameAssociationUi.Matched
        assertEquals(1007L, matchedFrame.globalFrameNumber)
        assertEquals(1007L, matched.jumpableFrame)

        val unmatched = TlsConnectionUiProjection.details(
            snapshot,
            associations = listOf(association(TlsAssociationState.UNMATCHED, TlsAssociationReason.NO_CLIENT_HELLO, frame = null))
        ).single()
        assertTrue(unmatched.frame is TlsFrameAssociationUi.Unmatched)
        assertNull("an unassociated connection has no frame to open", unmatched.jumpableFrame)

        val ambiguous = TlsConnectionUiProjection.details(
            snapshot,
            associations = listOf(association(TlsAssociationState.AMBIGUOUS, TlsAssociationReason.MULTIPLE_DESTINATIONS, frame = null))
        ).single()
        assertTrue(ambiguous.frame is TlsFrameAssociationUi.Unmatched)
        assertNull(ambiguous.jumpableFrame)

        val notCorrelated = TlsConnectionUiProjection.details(snapshot).single()
        assertEquals(TlsFrameAssociationUi.NotCorrelated, notCorrelated.frame)
        assertNull(notCorrelated.jumpableFrame)
    }

    @Test
    fun aMatchedStateWithoutAFrameStillDisablesTheJump() {
        val store = store()
        assertTrue(store.append(event(1L, "a", TlsConnectionPhase.CLOSED, clientRandom = CLIENT_RANDOM)))
        // Defensive: even if a "matched" association ever arrived without a frame,
        // no frame number may be exposed.
        val detail = TlsConnectionUiProjection.details(
            store.snapshot(),
            associations = listOf(association(TlsAssociationState.MATCHED, TlsAssociationReason.MATCHED, frame = null))
        ).single()
        assertTrue(detail.frame is TlsFrameAssociationUi.Unmatched)
        assertNull(detail.jumpableFrame)
    }

    @Test
    fun thePreviewPublishesAtMostOncePerC10Interval() {
        TlsConnectionPreviewStore.clear()
        val clock = AtomicLong(0L)
        val store = TlsConnectionStore(CAPTURE, TlsConnectionStoreLimits(), nanoTime = { clock.get() })

        assertTrue("the first paint is never delayed", TlsConnectionPreviewStore.publishIfDue(store))
        assertFalse("a second call inside the interval publishes nothing", TlsConnectionPreviewStore.publishIfDue(store))
        clock.addAndGet(249_000_000L)
        assertFalse(TlsConnectionPreviewStore.publishIfDue(store))
        clock.addAndGet(1_000_000L)
        assertTrue("250 ms is the gate", TlsConnectionPreviewStore.publishIfDue(store))
        TlsConnectionPreviewStore.clear()
    }

    private fun association(
        state: TlsAssociationState,
        reason: TlsAssociationReason,
        frame: Long?
    ) = TlsConnectionAssociation(
        captureId = CAPTURE,
        connectionId = "a",
        state = state,
        reason = reason,
        destinationIp = "203.0.113.10",
        destinationPort = 443,
        clientRandom = CLIENT_RANDOM,
        globalFrameNumber = frame,
        clientHelloFrames = if (frame != null) 1 else 0,
        helloRetryRequest = false
    )

    private companion object {
        const val CAPTURE = "live-306"
        const val BASE_WALL_MILLIS = 1_700_000_000_000L
        const val CLIENT_RANDOM = "0f1e2d3c4b5a69788796a5b4c3d2e1f00f1e2d3c4b5a69788796a5b4c3d2e1f0"
    }
}
