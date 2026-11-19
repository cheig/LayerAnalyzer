// Copyright (c) 2026 cheig
// LayerAnalyzer - https://github.com/cheig/LayerAnalyzer
// Licensed under GNU GPL version 3; see LICENSE.

package com.example.layanalyzer.data

import com.example.layanalyzer.capture.tls.TlsAssetErrorCode
import com.example.layanalyzer.capture.tls.TlsAssetException
import com.example.layanalyzer.capture.tls.TlsSecretAssetRef
import java.io.File
import kotlinx.coroutines.CoroutineDispatcher
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.NonCancellable
import kotlinx.coroutines.currentCoroutineContext
import kotlinx.coroutines.ensureActive
import kotlinx.coroutines.withContext

/**
 * Owns one private plaintext file. The analysis coordinator must retain this object
 * until native preferences AND loaded secret maps / dissection state have been cleared.
 * There is intentionally no shareable File/URI or untracked public path getter.
 */
class TlsAnalysisSecretLease internal constructor(
    val asset: TlsSecretAssetRef,
    private val keyLog: File,
    private val releaseFile: () -> Unit
) : AutoCloseable {
    private var closed = false
    private var configuringOrClosing = false
    private var configured = false
    private var clearNative: (() -> Unit)? = null

    /** Scoped TLS-311 export only; never exposes a reusable plaintext path. */
    @Synchronized
    internal fun copyForExplicitExport(output: java.io.OutputStream, checkCancelled: () -> Unit) {
        if (closed || configured || configuringOrClosing) throw TlsAssetException(TlsAssetErrorCode.IN_USE)
        keyLog.inputStream().use { input ->
            val buffer = ByteArray(8192)
            try {
                while (true) {
                    checkCancelled()
                    val count = input.read(buffer)
                    if (count < 0) break
                    output.write(buffer, 0, count)
                }
            } finally { buffer.fill(0) }
        }
    }

    /**
     * Registers cleanup BEFORE native sees the path, including a partially failed
     * configuration. Call once. The callback must throw unless native is fully cleared
     * (or its session destroyed); checking the native result envelope is mandatory.
     * TLS-105/106 supply the real callbacks and serialize their session/generation.
     * Do not release this lease just because configure or a redissection was cancelled.
     */
    @Synchronized
    fun <T> configureNative(clearNativeSecrets: () -> Unit, configure: (String) -> T): T {
        if (closed) throw TlsAssetException(TlsAssetErrorCode.CLOSED)
        if (configured || configuringOrClosing) throw TlsAssetException(TlsAssetErrorCode.IN_USE)
        configured = true
        clearNative = clearNativeSecrets
        configuringOrClosing = true
        try {
            return configure(keyLog.absolutePath)
        } finally {
            configuringOrClosing = false
        }
    }

    /** Cleanup failure leaves the file and its liveness lock intact; close can be retried. */
    @Synchronized
    override fun close() {
        if (closed) return
        if (configuringOrClosing) throw TlsAssetException(TlsAssetErrorCode.IN_USE)
        configuringOrClosing = true
        try {
            try {
                clearNative?.invoke()
            } catch (_: Exception) {
                // Native/provider exceptions can contain paths or secret material.
                throw TlsAssetException(TlsAssetErrorCode.NATIVE_CLEANUP_FAILED)
            }
            clearNative = null
            releaseFile()
            closed = true
        } finally {
            configuringOrClosing = false
        }
    }

    override fun toString(): String = "TlsAnalysisSecretLease(redacted=true)"
}

/**
 * Own a newly acquired lease before returning from IO. [consume] takes ownership
 * on entry (also on cancellation/failure); any cancellation before that transfer
 * closes the unconfigured lease even if IO had already completed successfully.
 */
internal suspend fun <T> withTlsAnalysisLease(
    io: CoroutineDispatcher = Dispatchers.IO,
    acquire: (checkCancelled: () -> Unit) -> TlsAnalysisSecretLease,
    consume: suspend (TlsAnalysisSecretLease) -> T
): T {
    val owner = currentCoroutineContext()
    var pending: TlsAnalysisSecretLease? = null
    try {
        withContext(NonCancellable + io) {
            owner.ensureActive()
            pending = acquire { owner.ensureActive() }
        }
        owner.ensureActive()
        val lease = checkNotNull(pending)
        pending = null
        return consume(lease)
    } finally {
        withContext(NonCancellable + io) { pending?.close() }
    }
}
