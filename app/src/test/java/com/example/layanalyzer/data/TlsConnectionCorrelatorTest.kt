// Copyright (c) 2026 cheig
// LayerAnalyzer - https://github.com/cheig/LayerAnalyzer
// Licensed under GNU GPL version 3; see LICENSE.

package com.example.layanalyzer.data

import com.example.layanalyzer.model.TlsConnectionEvent
import com.example.layanalyzer.model.TlsConnectionPhase
import java.io.File
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * Synthetic correlation cases for TLS-303: the parsed downstream client_random plus the
 * capture is what ties a proxy event to a real frame, so the same destination IP with
 * several connections never cross-wires, a repeated ClientHello (HelloRetryRequest or a
 * retransmission) stays one connection, and an unassociated event never carries an
 * invented frame number. No traffic, no secrets, no device and no native engine.
 */
class TlsConnectionCorrelatorTest {
    private val captureId = "capture-correlate"
    private val otherCapture = "capture-other"
    private val serverIp = "203.0.113.7"
    private val otherServerIp = "203.0.113.9"
    private val randomA = "a".repeat(64)
    private val randomB = "b".repeat(64)
    private val baseTime = 1_700_000_000_000L

    private val correlator = TlsConnectionCorrelator(captureId)

    /** The analysis frames are already the user's numbering, as a legacy single file is. */
    private val identity: TlsFrameMapping = TlsFrameMapping { it }

    private fun event(
        connection: String,
        sequence: Long,
        random: String? = null,
        ip: String = serverIp,
        port: Int = 443,
        wall: Long = baseTime,
        capture: String = captureId
    ) = TlsConnectionEvent(
        captureId = capture,
        connectionId = connection,
        eventSequence = sequence,
        monotonicNanos = sequence,
        wallTimeMillis = wall,
        destinationIp = ip,
        destinationPort = port,
        networkGeneration = 3,
        phase = TlsConnectionPhase.RELAYING,
        downstreamClientRandom = random
    )

    private fun observation(
        frame: Long,
        random: String,
        ip: String = serverIp,
        port: Int = 443,
        time: Long = baseTime
    ) = ClientHelloObservation(frame, time, random, ip, port)

    private fun association(events: List<TlsConnectionEvent>, observations: List<ClientHelloObservation>, mapping: TlsFrameMapping? = identity) =
        correlator.associate(events, observations, mapping)

    @Test
    fun sameDestinationConnectionsAreSeparatedByTheRandomNotTheIp() {
        val associations = association(
            events = listOf(
                event("connection-1", 1, random = randomA),
                event("connection-2", 2, random = randomB)
            ),
            // Both ClientHellos go to the same server, at almost the same time.
            observations = listOf(
                observation(20, randomB, time = baseTime + 500),
                observation(10, randomA, time = baseTime + 200)
            )
        )
        assertEquals(2, associations.size)
        val first = associations.single { it.connectionId == "connection-1" }
        assertEquals(TlsAssociationState.MATCHED, first.state)
        assertEquals(TlsAssociationReason.MATCHED, first.reason)
        assertEquals(10L, first.globalFrameNumber)
        assertEquals(1, first.clientHelloFrames)
        assertFalse(first.helloRetryRequest)
        // The second connection resolves to its own frame, not the first one's.
        assertEquals(20L, associations.single { it.connectionId == "connection-2" }.globalFrameNumber)
        // No app/UID attribution is ever implied (§8.4).
        assertFalse(first.originalApplicationKnown)
    }

    @Test
    fun duplicateAndOutOfOrderEventsForOneConnectionYieldOneAssociation() {
        val associations = association(
            // The same connection seen more than once, including a re-delivered event.
            events = listOf(
                event("connection-1", 5, random = randomA, wall = baseTime + 1_000),
                event("connection-1", 2, random = randomA, wall = baseTime),
                event("connection-1", 2, random = randomA, wall = baseTime),
                event("connection-1", 9, random = null, wall = baseTime + 2_000)
            ),
            observations = listOf(observation(10, randomA))
        )
        assertEquals(1, associations.size)
        val only = associations.single()
        assertEquals("connection-1", only.connectionId)
        assertEquals(TlsAssociationState.MATCHED, only.state)
        assertEquals(10L, only.globalFrameNumber)
    }

    @Test
    fun aMissingHandshakeIsUnmatchedAndNeverInventsAFrame() {
        val associations = association(
            events = listOf(event("connection-1", 1, random = randomA)),
            // The segment carrying this ClientHello was not merged: no observation exists.
            observations = listOf(observation(10, randomB))
        )
        val only = associations.single()
        assertEquals(TlsAssociationState.UNMATCHED, only.state)
        assertEquals(TlsAssociationReason.NO_CLIENT_HELLO, only.reason)
        assertNull(only.globalFrameNumber)
        assertEquals(0, only.clientHelloFrames)
    }

    @Test
    fun aConnectionWithoutAClientRandomIsUnmatched() {
        val only = association(
            events = listOf(event("connection-1", 1, random = null)),
            observations = listOf(observation(10, randomA))
        ).single()
        assertEquals(TlsAssociationState.UNMATCHED, only.state)
        assertEquals(TlsAssociationReason.NO_CLIENT_RANDOM, only.reason)
        assertNull(only.globalFrameNumber)
    }

    @Test
    fun helloRetryRequestIsOneMatchedConnectionNotAnAmbiguity() {
        // TLS 1.3 HelloRetryRequest: two ClientHellos share one client_random (RFC 8446).
        val only = association(
            events = listOf(event("connection-1", 1, random = randomA)),
            observations = listOf(
                observation(10, randomA, time = baseTime),
                observation(14, randomA, time = baseTime + 900)
            )
        ).single()
        assertEquals(TlsAssociationState.MATCHED, only.state)
        assertEquals(TlsAssociationReason.MATCHED, only.reason)
        assertTrue(only.helloRetryRequest)
        assertEquals(2, only.clientHelloFrames)
        // The documented rule reports the earliest ClientHello, and invents nothing.
        assertEquals(10L, only.globalFrameNumber)
    }

    @Test
    fun destinationAndTimeMismatchAreRefusedInsteadOfGuessed() {
        val destinationMismatch = association(
            events = listOf(event("connection-1", 1, random = randomA, ip = serverIp)),
            // The same random appears, but towards a different destination.
            observations = listOf(observation(10, randomA, ip = otherServerIp))
        ).single()
        assertEquals(TlsAssociationState.UNMATCHED, destinationMismatch.state)
        assertEquals(TlsAssociationReason.DESTINATION_MISMATCH, destinationMismatch.reason)
        assertNull(destinationMismatch.globalFrameNumber)

        val timeMismatch = association(
            events = listOf(event("connection-2", 1, random = randomB, wall = baseTime)),
            // Random and destination agree, but the frame is far outside the window.
            observations = listOf(observation(10, randomB, time = baseTime + 10 * 60_000))
        ).single()
        assertEquals(TlsAssociationState.UNMATCHED, timeMismatch.state)
        assertEquals(TlsAssociationReason.TIME_MISMATCH, timeMismatch.reason)
        assertNull(timeMismatch.globalFrameNumber)
    }

    @Test
    fun oneRandomAgainstTwoDestinationsIsHonestlyAmbiguous() {
        val only = association(
            events = listOf(event("connection-1", 1, random = randomA)),
            observations = listOf(
                observation(10, randomA, ip = serverIp),
                observation(30, randomA, ip = otherServerIp)
            )
        ).single()
        assertEquals(TlsAssociationState.AMBIGUOUS, only.state)
        assertEquals(TlsAssociationReason.MULTIPLE_DESTINATIONS, only.reason)
        assertNull("an ambiguous match must not publish a frame", only.globalFrameNumber)
    }

    @Test
    fun aMatchedFrameNumberIsTraceableThroughTheMergedMapping() {
        // TLS-302's merged source: only the second segment was merged, so merged position 1
        // is the manifest's global frame 1001. The correlator must report the global frame.
        val source = CaptureAnalysisSource.Merged(
            captureId = captureId,
            analysisFile = File("merged-analysis.pcap"),
            globalHeader = littleEndianHeader(),
            segments = listOf(
                SegmentFrameSpan("packets-0002.pcap", 1001L, 50L, 50L, 1L, 0L, "0".repeat(64), true)
            ),
            issues = emptyList(),
            manifestIssues = emptyList(),
            totalFrames = 50L,
            byteLength = 0L,
            singleSegment = true
        )
        val mapping = TlsFrameMapping.of(source)
        assertTrue(mapping != null)

        val matched = association(
            events = listOf(event("connection-1", 1, random = randomA)),
            observations = listOf(observation(7, randomA)),
            mapping = mapping
        ).single()
        assertEquals(TlsAssociationState.MATCHED, matched.state)
        assertEquals(1007L, matched.globalFrameNumber)

        // A frame outside the merged records has no global number; nothing is invented.
        val outside = association(
            events = listOf(event("connection-2", 2, random = randomB)),
            observations = listOf(observation(99, randomB)),
            mapping = mapping
        ).single()
        assertEquals(TlsAssociationState.UNMATCHED, outside.state)
        assertEquals(TlsAssociationReason.FRAME_NOT_IN_CAPTURE, outside.reason)
        assertNull(outside.globalFrameNumber)
    }

    @Test
    fun noAnalysisSourceMeansNoMatchedFrame() {
        val only = association(
            events = listOf(event("connection-1", 1, random = randomA)),
            observations = listOf(observation(10, randomA)),
            mapping = null
        ).single()
        assertEquals(TlsAssociationState.UNMATCHED, only.state)
        assertEquals(TlsAssociationReason.NO_FRAME_MAPPING, only.reason)
        assertNull(only.globalFrameNumber)
        assertNull(TlsFrameMapping.of(CaptureAnalysisSource.Missing(captureId)))
    }

    @Test
    fun eventsForAnotherCaptureAreIgnored() {
        val associations = association(
            events = listOf(event("connection-1", 1, random = randomA, capture = otherCapture)),
            observations = listOf(observation(10, randomA))
        )
        assertTrue(associations.isEmpty())
    }

    @Test
    fun theRandomComparisonIgnoresCaseAndSeparators() {
        val separated = randomA.chunked(2).joinToString(":").uppercase()
        val only = association(
            events = listOf(event("connection-1", 1, random = randomA)),
            observations = listOf(observation(10, separated))
        ).single()
        assertEquals(TlsAssociationState.MATCHED, only.state)
        assertEquals(10L, only.globalFrameNumber)
        assertEquals(randomA, only.clientRandom)
    }

    /** A minimal valid little-endian PCAP global header, as TLS-302 parses one. */
    private fun littleEndianHeader(): PcapGlobalHeader {
        val bytes = ByteArray(24)
        bytes[0] = 0xd4.toByte()
        bytes[1] = 0xc3.toByte()
        bytes[2] = 0xb2.toByte()
        bytes[3] = 0xa1.toByte()
        bytes[4] = 2
        bytes[6] = 4
        bytes[16] = 0xff.toByte()
        bytes[17] = 0xff.toByte()
        bytes[20] = 101
        return PcapGlobalHeader.parse(bytes)
    }
}
