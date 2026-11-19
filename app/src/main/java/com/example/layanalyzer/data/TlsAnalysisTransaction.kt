// Copyright (c) 2026 cheig; GPL-3.0.
package com.example.layanalyzer.data

import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.asStateFlow
import org.json.JSONObject
import java.util.concurrent.locks.ReentrantReadWriteLock
import java.util.concurrent.atomic.AtomicInteger
import kotlin.concurrent.withLock

/** Local revision prevents reuse even when native handles or file paths are reused. */
data class CaptureAnalysisRevision(
    val sessionHandle: Long = 0,
    val revision: Long = 0,
    val dissectionGeneration: Long = 0,
    val secretsGeneration: Long = 0,
    val configured: Boolean = false,
    val ready: Boolean = false
)

class StaleCaptureAnalysisException : CancellationException("Capture analysis changed.")

/** No suspension under this gate. JNI reads finish before configuration takes the write lock. */
internal class CaptureAnalysisGate {
    private val lock = ReentrantReadWriteLock(true)
    private val writers = AtomicInteger()
    private val mutableRevision = MutableStateFlow(CaptureAnalysisRevision())
    val revisions = mutableRevision.asStateFlow()

    fun publish(value: CaptureAnalysisRevision) { mutableRevision.value = value }

    inline fun <T> read(block: () -> T): T {
        val expected = revisions.value
        // Nested repository calls and transaction-owned reads already hold the gate.
        val nested = lock.readHoldCount > 0 || lock.isWriteLockedByCurrentThread
        if (!nested && (writers.get() > 0 || !lock.readLock().tryLock())) throw StaleCaptureAnalysisException()
        try {
            if (!nested && revisions.value != expected) throw StaleCaptureAnalysisException()
            val result = block()
            if (!nested && revisions.value != expected) throw StaleCaptureAnalysisException()
            return result
        } finally { if (!nested) lock.readLock().unlock() }
    }

    inline fun <T> exclusive(block: () -> T): T {
        writers.incrementAndGet()
        try { return lock.writeLock().withLock(block) }
        finally { writers.decrementAndGet() }
    }
}

internal data class NativeTlsConfiguration(
    val success: Boolean,
    val dissectionGeneration: Long,
    val secretsGeneration: Long,
    val configured: Boolean,
    val sessionClosed: Boolean,
    val errorCode: String? = null
) {
    companion object {
        fun parse(raw: String): NativeTlsConfiguration {
            val json = JSONObject(raw)
            require(json.getInt("schemaVersion") == 1)
            val success = json.getBoolean("success")
            return NativeTlsConfiguration(
                success, json.optLong("dissectionGeneration", -1),
                json.optLong("secretsGeneration", -1), json.optBoolean("configured"),
                json.getBoolean("sessionClosed"),
                if (success) null else json.optString("errorCode", "IO_ERROR")
            )
        }
    }
}

/**
 * One priming frame's plaintext verdict: counts and identity, never a label,
 * offset or payload byte.
 *
 * [streamId] is the frame's `tcp.stream` (-1 when the frame has no TCP layer) and
 * [tlsVersion] the wire version of the records that carried the plaintext
 * (`0x0304` TLS 1.3, `0x0303` TLS 1.2, `0` when the frame cannot tell). The two
 * travel with the counts because a decryption verdict belongs to a connection,
 * not to a frame: the caller aggregates by [streamId] and classifies by
 * [tlsVersion] (see `TlsPlaintextTally`).
 */
internal data class NativePlaintextProbe(
    val decryptedSources: Int,
    val decryptedBytes: Long,
    val observed: Boolean,
    val streamId: Int,
    val tlsVersion: Int
) {
    companion object {
        private const val MAX_SOURCES = 4096

        /**
         * Null means "native did not answer with a usable verdict", never "no
         * plaintext". The scan treats that as a dissection failure and the caller
         * fails closed, so a malformed reply can never light the observation flag.
         */
        fun parse(raw: String): NativePlaintextProbe? = runCatching {
            val json = JSONObject(raw)
            require(json.getInt("schemaVersion") == 1)
            require(json.getBoolean("success"))
            val sources = json.getInt("decryptedSources")
            val bytes = json.getLong("decryptedBytes")
            val observed = json.getBoolean("observed")
            val stream = json.getInt("streamId")
            val version = json.getInt("tlsVersion")
            require(sources in 0..MAX_SOURCES && bytes >= 0L)
            // Plaintext needs real bytes, and observation needs plaintext.
            require(!observed || (sources > 0 && bytes > 0L))
            require(stream >= -1)
            // The range is the wire width, not a whitelist: a version this build
            // does not know (DTLS, a future protocol) must not fail the whole
            // analysis, it just stays unidentified in the report.
            require(version in 0..0xFFFF)
            // Identity is only read for a frame that carried plaintext, so a zero
            // count with a stream or version attached is not a reply this build
            // produced.
            require(sources > 0 || (stream == -1 && version == 0))
            NativePlaintextProbe(sources, bytes, observed, stream, version)
        }.getOrNull()
    }
}

data class TlsAnalysisResult(
    val success: Boolean,
    val analysis: CaptureAnalysisRevision,
    val visibleFrameCount: Int = 0,
    val errorCode: String? = null,
    val reopenRequired: Boolean = false,
    val observedDecryptedData: Boolean = false,
    /**
     * The totals behind [observedDecryptedData]: how many connections decrypted
     * and under which TLS version. [TlsPlaintextStats.EMPTY] on any failure, which
     * is "not measured", never "nothing decrypted".
     */
    val plaintextStats: TlsPlaintextStats = TlsPlaintextStats.EMPTY
)

/** Production JNI is injected only here; JVM tests exercise the real transaction and gate. */
internal interface TlsAnalysisBackend {
    fun configure(path: String?, revision: Long): NativeTlsConfiguration
    fun frameCount(): Int
    fun dissectFrame(packetIndex: Int): Boolean
    fun restoreFilter(filter: String): Int
    fun closeSession()
    fun invalidateCaches()
    /** Native is destroyed and every retained secret lease has released its plaintext. */
    fun onClosed() {}
    /**
     * Totals of the scan that just ran, read once per analysis. The verdict is
     * [TlsPlaintextStats.observed] — a decrypted data source that carried bytes —
     * and never "a keylog was configured".
     */
    fun plaintextStats(): TlsPlaintextStats = TlsPlaintextStats.EMPTY
}

private class TlsConfigurationFailure(val code: String) : IllegalStateException("TLS configuration failed.")

/** Owns secret leases, including failed deletion retries. Never exposes their paths. */
internal class TlsAnalysisTransaction(
    private val gate: CaptureAnalysisGate,
    private val backend: TlsAnalysisBackend
) {
    private var nativeLease: TlsAnalysisSecretLease? = null
    private var nativePath: String? = null
    private val retainedLeases = mutableSetOf<TlsAnalysisSecretLease>()

    fun opened(handle: Long) = gate.exclusive {
        gate.publish(CaptureAnalysisRevision(handle, gate.revisions.value.revision + 1, ready = true))
    }

    fun close() = gate.exclusive {
        backend.closeSession() // must finish all native destructors before deleting plaintext
        nativeLease = null
        nativePath = null
        gate.publish(CaptureAnalysisRevision(revision = gate.revisions.value.revision + 1))
        backend.invalidateCaches()
        releaseRetained()
        backend.onClosed()
    }

    fun configure(
        lease: TlsAnalysisSecretLease?,
        expected: CaptureAnalysisRevision,
        filter: String,
        checkCancelled: () -> Unit,
        progress: (Int, Int) -> Unit
    ): TlsAnalysisResult = gate.exclusive {
        // Ownership transfers even for a stale request. An already-owned lease is not reusable.
        if (lease != null && lease in retainedLeases) {
            return@exclusive TlsAnalysisResult(false, gate.revisions.value, errorCode = "INVALID_ARGUMENT")
        }
        if (lease != null) retainedLeases.add(lease)
        if (expected != gate.revisions.value || expected.sessionHandle == 0L || !expected.ready) {
            releaseRetained(except = nativeLease)
            return@exclusive TlsAnalysisResult(false, gate.revisions.value, errorCode = "STALE_GENERATION")
        }
        val changing = expected.copy(revision = expected.revision + 1, ready = false)
        gate.publish(changing)
        try {
            checkCancelled()
            check(expected.secretsGeneration < Long.MAX_VALUE)
            val revision = expected.secretsGeneration + 1
            var configuredPath: String? = null
            val configured = if (lease == null) backend.configure(null, revision) else {
                lease.configureNative(clearNativeSecrets = {
                    // A replacement has already rebuilt epan, or close has destroyed it.
                    // An external/uncoordinated close may never clear a newer configuration.
                    check(nativeLease !== lease) { "TLS configuration still owns this lease." }
                }) { path -> configuredPath = path; backend.configure(path, revision) }
            }
            if (!configured.success) throw TlsConfigurationFailure(configured.errorCode ?: "IO_ERROR")
            check(!configured.sessionClosed &&
                configured.secretsGeneration == revision &&
                configured.dissectionGeneration > expected.dissectionGeneration &&
                configured.configured == (lease != null))
            nativeLease = lease
            nativePath = configuredPath
            releaseRetained(except = lease)
            backend.invalidateCaches()
            val total = backend.frameCount()
            check(total >= 0)
            progress(0, total)
            for (index in 0 until total) {
                checkCancelled()
                check(backend.dissectFrame(index)) { "Unable to dissect capture." }
                if ((index + 1) % 64 == 0 || index + 1 == total) progress(index + 1, total)
            }
            checkCancelled()
            val visible = backend.restoreFilter(filter)
            check(visible >= 0)
            checkCancelled()
            val ready = changing.copy(
                dissectionGeneration = configured.dissectionGeneration,
                secretsGeneration = revision, configured = configured.configured, ready = true
            )
            gate.publish(ready)
            // Ready means the scan finished. It does not assert any TLS plaintext exists,
            // and the counts alone never raise the verdict: only a decrypted source with
            // bytes does that, inside the backend.
            val plaintext = backend.plaintextStats()
            TlsAnalysisResult(true, ready, visible, observedDecryptedData = plaintext.observed,
                plaintextStats = plaintext)
        } catch (error: Throwable) {
            // Configuration may have reached native even when JSON parsing/JNI failed.
            // A rollback cannot restore a destroyed epan; close is the safe explicit state.
            close()
            if (error is CancellationException) throw error
            TlsAnalysisResult(false, gate.revisions.value, errorCode = when (error) {
                is TlsConfigurationFailure -> error.code
                is LinkageError -> "UNSUPPORTED"
                else -> "IO_ERROR"
            }, reopenRequired = true)
        }
    }

    /** Decode As and other existing settings can also rebuild epan. Same revision is an
     * idempotent native query, not another reset, so snapshot consumers see the actual generation. */
    fun <T> changeDissectionSettings(block: () -> T): T = gate.exclusive {
        val result = block()
        val before = gate.revisions.value
        if (before.sessionHandle != 0L) {
            try {
                val current = backend.configure(nativePath, before.secretsGeneration)
                check(current.success && !current.sessionClosed && current.secretsGeneration == before.secretsGeneration)
                if (current.dissectionGeneration != before.dissectionGeneration) {
                    backend.invalidateCaches()
                    gate.publish(before.copy(revision = before.revision + 1, dissectionGeneration = current.dissectionGeneration))
                }
            } catch (_: Exception) {
                close()
                throw IllegalStateException("Analysis configuration failed. Reopen the capture.")
            }
        }
        result
    }

    private fun releaseRetained(except: TlsAnalysisSecretLease? = null) {
        val failures = retainedLeases.filter { it !== except }.filter { lease ->
            try { lease.close(); false } catch (_: Exception) { true }
        }.toSet()
        retainedLeases.retainAll(failures + listOfNotNull(except))
        check(failures.isEmpty()) { "Unable to release TLS analysis secrets." }
    }
}
