// Copyright (c) 2026 cheig; GPL-3.0.
package com.example.layanalyzer.data

/**
 * The TLS version of the records that carried a connection's plaintext.
 *
 * [UNKNOWN] is a real answer, not a failure: the analyser only claims a version
 * when the decrypted record itself said which one it was, and a stream that
 * never produced such a record stays unidentified rather than being guessed from
 * the port, the host, or a configured keylog.
 */
enum class TlsPlaintextVersion {
    TLS_1_3,
    TLS_1_2,

    /** SSL 3.0 through TLS 1.1: decrypted, but not the 1.2/1.3 split this reports. */
    EARLIER,

    UNKNOWN;

    companion object {
        /**
         * Maps the native probe's wire value. TLS 1.3 is never read from a record
         * header -- every 1.3 record header claims 0x0303 -- so `0x0304` only
         * arrives when the dissector saw an actual 1.3 record (`tls.record.opaque_type`).
         *
         * Any other value stays [UNKNOWN] instead of failing the analysis: a DTLS
         * record or a version this build does not model is a real thing to see in
         * a capture, and the report says "not identified" rather than guessing.
         */
        fun fromWire(value: Int): TlsPlaintextVersion = when {
            value == 0x0304 -> TLS_1_3
            value == 0x0303 -> TLS_1_2
            value in 0x0300..0x0302 -> EARLIER
            else -> UNKNOWN
        }
    }
}

/**
 * What one analysis recovered from the capture, per connection and per version
 * (P2-3). Counts only: a decrypted connection is a `tcp.stream` with at least
 * one decrypted data source, never a proxy that merely completed a handshake
 * (C03 7, §10.2).
 *
 * [observed] is the same verdict the key-log page renders, and it is true only
 * when a decrypted source carried bytes. [decryptedRecords] counts data sources
 * (one per decrypted record), [decryptedBytes] their reported lengths.
 */
data class TlsPlaintextStats(
    val connections: Int = 0,
    val tls13Connections: Int = 0,
    val tls12Connections: Int = 0,
    val earlierConnections: Int = 0,
    val unidentifiedConnections: Int = 0,
    val decryptedRecords: Long = 0,
    val decryptedBytes: Long = 0,
    val observed: Boolean = false,
    val scannedFrames: Int = 0
) {
    /** Connections that decrypted, but not under TLS 1.2 or 1.3. */
    val otherConnections: Int get() = earlierConnections + unidentifiedConnections

    val hasVersionBreakdown: Boolean get() = tls13Connections > 0 || tls12Connections > 0

    companion object {
        /** Nothing was analysed: not "no plaintext", but "no verdict yet". */
        val EMPTY = TlsPlaintextStats()
    }
}

/**
 * Folds one primed frame at a time into [TlsPlaintextStats].
 *
 * The scan reports per frame, but a decryption verdict belongs to a connection,
 * so frames are aggregated by `tcp.stream` first: a stream counts once no matter
 * how many of its frames decrypted, and its version is the first version any of
 * its decrypted records declared. A frame with no `tcp.stream` cannot be
 * attributed, so it is kept as one "unattributed" connection instead of being
 * silently added to a real one or dropped from the total.
 *
 * Not thread-safe on purpose: it is only touched by the single analysis scan.
 */
internal class TlsPlaintextTally {
    private class Connection(var version: TlsPlaintextVersion, var records: Long = 0, var bytes: Long = 0)

    private val byStream = LinkedHashMap<Int, Connection>()
    private var unattributed: Connection? = null
    private var records = 0L
    private var bytes = 0L
    private var scannedFrames = 0
    private var observed = false

    fun reset() {
        byStream.clear()
        unattributed = null
        records = 0
        bytes = 0
        scannedFrames = 0
        observed = false
    }

    fun record(probe: NativePlaintextProbe) {
        scannedFrames++
        if (probe.observed) observed = true
        if (probe.decryptedSources <= 0) return
        val version = TlsPlaintextVersion.fromWire(probe.tlsVersion)
        val connection = if (probe.streamId >= 0) {
            byStream.getOrPut(probe.streamId) { Connection(version) }
        } else {
            unattributed ?: Connection(version).also { unattributed = it }
        }
        // A record that could not name its version must not freeze the
        // connection at UNKNOWN; a second *known* but different version is a
        // renegotiation this report does not claim to model, so the first wins.
        if (connection.version == TlsPlaintextVersion.UNKNOWN) connection.version = version
        connection.records += probe.decryptedSources
        connection.bytes += probe.decryptedBytes
        records += probe.decryptedSources
        bytes += probe.decryptedBytes
    }

    fun stats(): TlsPlaintextStats {
        val all = byStream.values + listOfNotNull(unattributed)
        fun count(version: TlsPlaintextVersion) = all.count { it.version == version }
        return TlsPlaintextStats(
            connections = all.size,
            tls13Connections = count(TlsPlaintextVersion.TLS_1_3),
            tls12Connections = count(TlsPlaintextVersion.TLS_1_2),
            earlierConnections = count(TlsPlaintextVersion.EARLIER),
            unidentifiedConnections = count(TlsPlaintextVersion.UNKNOWN),
            decryptedRecords = records,
            decryptedBytes = bytes,
            observed = observed,
            scannedFrames = scannedFrames
        )
    }
}
