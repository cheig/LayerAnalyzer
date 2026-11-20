// Copyright (c) 2026 cheig; GPL-3.0.
package com.example.layanalyzer.data

import org.junit.Assert.*
import org.junit.Test

/**
 * P2-3: a decryption verdict belongs to a connection, not to a frame, so the scan's
 * per-frame counts are folded by `tcp.stream` and classified by the version the
 * plaintext arrived under.
 */
class TlsPlaintextStatsTest {
    private fun plaintext(stream: Int, version: Int, sources: Int = 1, bytes: Long = 16L) =
        NativePlaintextProbe(sources, bytes, sources > 0 && bytes > 0L, stream, version)

    private fun noPlaintext() = NativePlaintextProbe(0, 0, false, -1, 0)

    @Test fun countsAreTotalsNotTheFirstHit() {
        val tally = TlsPlaintextTally()
        repeat(10) { tally.record(plaintext(stream = 4, version = 0x0303)) }
        tally.record(noPlaintext())
        val stats = tally.stats()
        // Ten frames, one connection: the counters stopped at the first hit before.
        assertEquals(1, stats.connections)
        assertEquals(10L, stats.decryptedRecords)
        assertEquals(160L, stats.decryptedBytes)
        assertEquals(11, stats.scannedFrames)
        assertTrue(stats.observed)
    }

    @Test fun oneConnectionCountsOnceNoMatterHowManyFramesDecrypted() {
        val tally = TlsPlaintextTally()
        tally.record(plaintext(stream = 4, version = 0x0303))
        tally.record(plaintext(stream = 4, version = 0x0303))
        tally.record(plaintext(stream = 7, version = 0x0303))
        assertEquals(2, tally.stats().connections)
        assertEquals(3L, tally.stats().decryptedRecords)
    }

    @Test fun theVersionSplitSeparatesTls13FromTls12() {
        val tally = TlsPlaintextTally()
        tally.record(plaintext(stream = 1, version = 0x0304))
        tally.record(plaintext(stream = 2, version = 0x0304))
        tally.record(plaintext(stream = 3, version = 0x0303))
        val stats = tally.stats()
        assertEquals(3, stats.connections)
        assertEquals(2, stats.tls13Connections)
        assertEquals(1, stats.tls12Connections)
        assertEquals(0, stats.otherConnections)
        assertTrue(stats.hasVersionBreakdown)
    }

    @Test fun aConnectionThatCouldNotNameItsVersionNeverFreezesAtUnknown() {
        val tally = TlsPlaintextTally()
        // First frame could not tell; the second one could, and it decides.
        tally.record(plaintext(stream = 9, version = 0))
        tally.record(plaintext(stream = 9, version = 0x0304))
        assertEquals(1, tally.stats().tls13Connections)
        assertEquals(0, tally.stats().unidentifiedConnections)
    }

    @Test fun recordVersionsOlderThanTls12AreReportedAsSuchNotAsUnidentified() {
        val tally = TlsPlaintextTally()
        tally.record(plaintext(stream = 1, version = 0x0301)) // TLS 1.0
        tally.record(plaintext(stream = 2, version = 0x0300)) // SSL 3.0
        tally.record(plaintext(stream = 3, version = 0))
        tally.record(plaintext(stream = 4, version = 0xFEFD)) // DTLS 1.2: not this split
        val stats = tally.stats()
        assertEquals(2, stats.earlierConnections)
        assertEquals(2, stats.unidentifiedConnections)
        assertEquals(4, stats.otherConnections)
        assertFalse(stats.hasVersionBreakdown)
    }

    @Test fun aFrameWithoutAConnectionIsKeptAsOneUnattributedConnection() {
        val tally = TlsPlaintextTally()
        tally.record(plaintext(stream = -1, version = 0x0303))
        tally.record(plaintext(stream = -1, version = 0x0303))
        tally.record(plaintext(stream = 3, version = 0x0303))
        // Never silently merged into a real stream, and never silently dropped.
        assertEquals(2, tally.stats().connections)
        assertEquals(3L, tally.stats().decryptedRecords)
    }

    @Test fun anEmptyTallyClaimsNothing() {
        val stats = TlsPlaintextTally().stats()
        assertEquals(TlsPlaintextStats.EMPTY, stats)
        assertFalse(stats.observed)
        assertFalse(stats.hasVersionBreakdown)
    }

    @Test fun resetStartsTheNextAnalysisFromZero() {
        val tally = TlsPlaintextTally()
        tally.record(plaintext(stream = 1, version = 0x0304))
        tally.reset()
        assertEquals(TlsPlaintextStats.EMPTY, tally.stats())
        tally.record(plaintext(stream = 1, version = 0x0303))
        assertEquals(1, tally.stats().tls12Connections)
        assertEquals(0, tally.stats().tls13Connections)
    }

    @Test fun aZeroLengthRecordIsCountedButNeverObserved() {
        val tally = TlsPlaintextTally()
        tally.record(plaintext(stream = 1, version = 0x0303, sources = 1, bytes = 0L))
        val stats = tally.stats()
        assertEquals(1, stats.connections)
        assertEquals(1L, stats.decryptedRecords)
        assertFalse(stats.observed)
    }
}
