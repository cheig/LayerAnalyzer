// Copyright (c) 2026 cheig
// LayerAnalyzer - https://github.com/cheig/LayerAnalyzer
// Licensed under GNU GPL version 3; see LICENSE.

package com.example.layanalyzer.capture.tls

import java.io.File
import java.io.RandomAccessFile
import java.util.ArrayDeque
import java.util.concurrent.locks.ReentrantLock
import kotlin.concurrent.withLock

/**
 * One live capture's secret-persistence state. Counters and fixed codes only: a
 * value of this type is safe in an event, a UI state or a log, and never carries
 * a label, a client random or a secret byte.
 *
 * [accepted] counts records copied into the bounded queue, which is what the C05
 * `offerSecret` callback reports as OK; [persisted] counts records that have been
 * encrypted and synced by the container. They are deliberately separate: C05
 * states that accepted is not persisted, and only the consumer that finishes a
 * record may advance the watermark.
 */
data class TlsSecretPersistence(
    val accepted: Long,
    val persisted: Long,
    val rejected: Long,
    val failure: TlsAssetErrorCode?,
    val asset: TlsSecretAssetRef?
) {
    /**
     * True only when every record the engine produced was encrypted and synced,
     * nothing was refused at the queue, and nothing failed. A capture with no
     * intercepted connection is vacuously complete and has no asset.
     */
    val complete: Boolean get() = failure == null && rejected == 0L && accepted == persisted

    /**
     * Design §8.2's "no new MITM" condition: while this is true the connection
     * engine must pass new candidates through untouched, because their secrets
     * could not be saved. Established connections keep forwarding.
     */
    val mitmSuspended: Boolean get() = failure != null || rejected > 0L

    override fun toString(): String =
        "TlsSecretPersistence(accepted=$accepted, persisted=$persisted, rejected=$rejected, " +
            "failure=$failure, published=${asset != null}, complete=$complete)"
}

/** Canonical queue arrays only; excludes parser/encryption temporaries and object overhead. */
data class TlsSecretQueueMetrics(
    val pendingBytes: Long,
    val pendingRecords: Int,
    val inFlightBytes: Long,
    val peakPendingBytes: Long,
    val peakPendingRecords: Int,
    val peakRetainedBytes: Long,
    val queueLimitBytes: Long,
    val accepted: Long,
    val persisted: Long,
    val rejected: Long,
    val consumerAlive: Boolean,
    val abandoned: Boolean
)

/** Budgets of the live path. A zero-free value above a ceiling is rejected, not clamped (C03 9). */
internal data class TlsLiveSecretLimits(
    val queueBytes: Long = DEFAULT_QUEUE_BYTES,
    val drainTimeoutMillis: Long = DEFAULT_DRAIN_MILLIS,
    val asset: TlsAssetLimits = TlsAssetLimits()
) {
    init {
        if (queueBytes !in 1..MAX_QUEUE_BYTES || drainTimeoutMillis !in 1..MAX_DRAIN_MILLIS) {
            throw TlsAssetException(TlsAssetErrorCode.INVALID_ARGUMENT)
        }
    }

    companion object {
        /** C10's secrets enqueue budget, shared by every connection of one capture. */
        const val DEFAULT_QUEUE_BYTES = 1L * 1024 * 1024
        const val MAX_QUEUE_BYTES = DEFAULT_QUEUE_BYTES

        /** C10's stop-writer wait: the drain is bounded, never indefinite. */
        const val DEFAULT_DRAIN_MILLIS = 5_000L
        const val MAX_DRAIN_MILLIS = DEFAULT_DRAIN_MILLIS
    }
}

/** What a live sink needs from the store that created it; never exposed outside the package. */
internal class TlsLiveSecretTarget(
    val captureId: String,
    val assetId: String,
    val encrypted: File,
    val asset: TlsEncryptedAsset,
    /** Publishes the index for a watermark, after which the asset is the current one. */
    val publish: (TlsAssetWatermark) -> TlsSecretAssetRef,
    /** Removes the unpublished asset: only safe once the consumer has returned. */
    val discard: () -> Unit,
    /** Drops the active registration without deleting, for a consumer that has returned. */
    val detach: () -> Unit
)

/**
 * The real-time downstream secret path of one capture (design §8.1, §8.2).
 *
 * The Go engine's per-connection keylog writer hands each complete NSS line to
 * `TlsPlatformCallbacks.offerSecret`, which calls [offer]. Offer copies the bytes
 * into a bounded queue and returns immediately: no disk I/O, no waiting, nothing
 * that could stall a handshake. A single consumer thread takes records off that
 * queue and encrypts each one into the TLS-103 container, so a record is
 * persisted only once its record has been written and synced.
 *
 * A record that cannot be queued is lost, not fatal. The sink records it, marks
 * the capture incomplete and suspends new interception ([TlsSecretPersistence.mitmSuspended]);
 * the connection it came from keeps forwarding, and so do all the others (§8.2).
 *
 * [finish] ends admission, waits for the accepted records to drain within C10's
 * stop-writer budget, and publishes the watermark that was actually reached.
 * Records still unpersisted when that budget passes are reported as incomplete
 * rather than flushed away, so nothing is ever claimed complete on the strength
 * of a flush alone.
 */
class TlsLiveSecretSink internal constructor(
    private val target: TlsLiveSecretTarget,
    private val limits: TlsLiveSecretLimits,
    threadFactory: (Runnable) -> Thread = DEFAULT_THREAD_FACTORY
) : AutoCloseable {

    private val lock = ReentrantLock()
    private val ready = lock.newCondition()
    private val pending = ArrayDeque<ByteArray>()

    private var pendingBytes = 0L
    private var inFlightBytes = 0L
    private var peakPendingBytes = 0L
    private var peakPendingRecords = 0
    private var peakRetainedBytes = 0L
    private var accepting = true
    private var finished = false
    private var abandoned = false
    private var failure: TlsAssetErrorCode? = null
    private var watermark: TlsAssetWatermark? = null
    private var published: TlsSecretAssetRef? = null
    private var accepted = 0L
    private var persisted = 0L
    private var rejected = 0L

    private val consumer = threadFactory(Runnable { consume() })

    init {
        consumer.start()
    }

    /**
     * Copies one NSS line into the bounded queue. Returns true when the record was
     * accepted, which is what C05's `offerSecret` reports to Go; false means the
     * record is lost. Never blocks and never performs I/O.
     */
    fun offer(connectionId: String, line: ByteArray): Boolean {
        val record = canonicalRecord(connectionId, line)
        lock.withLock {
            if (record == null || !accepting || failure != null || pendingBytes + record.size > limits.queueBytes) {
                record?.fill(0)
                rejected++
                return false
            }
            pending.addLast(record)
            pendingBytes += record.size
            accepted++
            peakPendingBytes = maxOf(peakPendingBytes, pendingBytes)
            peakPendingRecords = maxOf(peakPendingRecords, pending.size)
            peakRetainedBytes = maxOf(peakRetainedBytes, pendingBytes + inFlightBytes)
            ready.signalAll()
            return true
        }
    }

    /** A consistent snapshot; safe to call while records are still arriving. */
    fun snapshot(): TlsSecretPersistence = lock.withLock { persistenceLocked() }

    /** Queued bytes only; excludes the record currently being encrypted/synced. */
    fun queuedBytes(): Long = lock.withLock { pendingBytes }

    fun queueMetrics(): TlsSecretQueueMetrics = lock.withLock {
        TlsSecretQueueMetrics(pendingBytes, pending.size, inFlightBytes,
            peakPendingBytes, peakPendingRecords, peakRetainedBytes, limits.queueBytes,
            accepted, persisted, rejected, consumer.isAlive, abandoned)
    }

    /**
     * Ends admission, drains the accepted records inside the stop-writer budget,
     * and publishes the watermark actually reached. Idempotent: later calls return
     * the same result. It does not stop the engine, only this sink's admission.
     */
    fun finish(): TlsSecretPersistence {
        lock.withLock {
            if (finished) return persistenceLocked()
            accepting = false
            ready.signalAll()
        }
        consumer.join(limits.drainTimeoutMillis)
        if (consumer.isAlive) {
            // Waiting longer is exactly what C10 forbids. The records the consumer
            // has not reached stay unpersisted and the asset stays unpublished, so
            // the directory must not become sweepable yet: the consumer still holds
            // it open, and it is the consumer that releases it (see consume).
            lock.withLock {
                abandoned = true
                finished = true
                if (failure == null) failure = TlsAssetErrorCode.IO_ERROR
            }
            return snapshot()
        }
        closeAsset()
        val mark = lock.withLock { watermark }
        val reference = try {
            if (mark != null && mark.sequence > 0 && truncateTo(mark)) target.publish(mark) else {
                // Nothing was persisted (or the tail could not be cut back to the
                // last synced record), so no index may point at this asset.
                target.discard()
                null
            }
        } catch (error: Exception) {
            target.discard()
            lock.withLock {
                if (failure == null) failure = (error as? TlsAssetException)?.code ?: TlsAssetErrorCode.IO_ERROR
                finished = true
            }
            throw error
        }
        lock.withLock {
            finished = true
            published = reference
        }
        return snapshot()
    }

    override fun close() {
        finish()
    }

    private fun consume() {
        try {
            while (true) {
                val record = lock.withLock {
                    while (pending.isEmpty() && accepting) {
                        try {
                            ready.await()
                        } catch (_: InterruptedException) {
                            return
                        }
                    }
                    if (pending.isEmpty()) return
                    val next = pending.removeFirst().also { pendingBytes -= it.size }
                    // A sink that gave up on its stop budget publishes nothing, so a
                    // record taken after that point is not persisted either. Without
                    // this the report would understate what reached the disk.
                    if (abandoned) {
                        next.fill(0)
                        null
                    } else {
                        inFlightBytes = next.size.toLong()
                        next
                    }
                } ?: continue
                try {
                    val mark = target.asset.append(record)
                    lock.withLock {
                        watermark = mark
                        persisted++
                    }
                } catch (error: Exception) {
                    // A record that was not synced is not persisted, and the container
                    // refuses further appends once a write is uncertain. The records
                    // still queued stay counted as accepted-but-not-persisted, which is
                    // what makes the state incomplete.
                    lock.withLock { failure = (error as? TlsAssetException)?.code ?: TlsAssetErrorCode.IO_ERROR }
                    return
                } finally {
                    record.fill(0)
                    lock.withLock { inFlightBytes = 0L }
                }
            }
        } finally {
            lock.withLock {
                pending.forEach { it.fill(0) }
                pending.clear()
                pendingBytes = 0L
                inFlightBytes = 0L
            }
            // The container is always closed here, including on the path where the
            // stop budget expired first: otherwise a sink that gave up waiting would
            // leave the file lock and the key material held by a thread nobody joins.
            closeAsset()
            // A consumer that returns after its sink gave up is the one that makes
            // the unpublished directory safe to sweep, so it is the one that
            // releases it.
            if (lock.withLock { abandoned }) target.detach()
        }
    }

    private fun closeAsset() {
        try {
            target.asset.close()
        } catch (_: Exception) {
            lock.withLock { if (failure == null) failure = TlsAssetErrorCode.IO_ERROR }
        }
    }

    /**
     * Cuts the container back to the last synced record. Only the final record can
     * be partial, and only when its own write did not finish, so this keeps the
     * asset openable by the analysis lease instead of leaving a truncated tail.
     */
    private fun truncateTo(mark: TlsAssetWatermark): Boolean = try {
        RandomAccessFile(target.encrypted, "rw").use { file ->
            if (file.length() > mark.fileBytes) {
                file.setLength(mark.fileBytes)
                file.fd.sync()
            }
        }
        true
    } catch (_: Exception) {
        lock.withLock { if (failure == null) failure = TlsAssetErrorCode.IO_ERROR }
        false
    }

    /**
     * Validates one offered line with the same rules the import path applies, and
     * returns the canonical NSS bytes to persist. A line the analysis lease would
     * later refuse is refused here, so an asset this sink writes is always one the
     * lease can open.
     */
    private fun canonicalRecord(connectionId: String, line: ByteArray): ByteArray? {
        if (!TlsAssetIdentity.validId(connectionId)) return null
        if (line.isEmpty() || line.size > KeyLogParser.MAX_LINE_BYTES) return null
        val parsed = KeyLogParser.parse(line.inputStream()) as? KeyLogParseResult.Success ?: return null
        val record = parsed.records.singleOrNull() ?: return null
        return record.toNssLine().toByteArray(Charsets.US_ASCII)
    }

    private fun persistenceLocked() =
        TlsSecretPersistence(accepted, persisted, rejected, failure, published)

    companion object {
        /** Daemon: a sink that is never finished must not keep a process alive. */
        internal val DEFAULT_THREAD_FACTORY: (Runnable) -> Thread = { runnable ->
            Thread(runnable, "tls-live-secrets").apply { isDaemon = true }
        }
    }
}
