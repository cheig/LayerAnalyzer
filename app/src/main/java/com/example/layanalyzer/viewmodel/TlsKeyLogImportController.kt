// Copyright (c) 2026 cheig; GPL-3.0.
package com.example.layanalyzer.viewmodel

import com.example.layanalyzer.capture.tls.*
import com.example.layanalyzer.data.*
import com.example.layanalyzer.model.TlsErrorCode
import kotlinx.coroutines.*
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.flow.update
import java.io.FilterInputStream
import java.io.InputStream
import java.util.concurrent.ConcurrentHashMap

enum class TlsKeyLogImportPhase { Idle, Selecting, Reading, Saving, Redissection, Cancelling }

/** Metadata only: neither URI/path nor key records belong in observable UI state. */
data class TlsKeyLogImportState(
    val phase: TlsKeyLogImportPhase = TlsKeyLogImportPhase.Idle,
    val configured: Boolean = false,
    val observedDecryptedData: Boolean = false,
    /**
     * Totals behind [observedDecryptedData]: connections that decrypted, split by
     * the TLS version they decrypted under. Empty unless the observation belongs
     * to the current analysis, so a stale count can never outlive its revision.
     */
    val plaintextStats: TlsPlaintextStats = TlsPlaintextStats.EMPTY,
    val processedFrames: Int = 0,
    val totalFrames: Int = 0,
    val importedRecords: Int = 0,
    val duplicateLines: Int = 0,
    val unsupportedLines: Int = 0,
    val parseError: KeyLogParseError? = null,
    val errorCode: String? = null,
    val cancelled: Boolean = false,
    val reopenRequired: Boolean = false
) {
    val busy: Boolean get() = phase != TlsKeyLogImportPhase.Idle
}

internal data class TlsKeyLogImportTarget(
    val captureId: String,
    val session: CaptureSessionToken,
    val analysis: CaptureAnalysisRevision
)

internal interface TlsKeyLogImportBackend {
    fun currentTarget(): TlsKeyLogImportTarget?
    fun currentAnalysis(): CaptureAnalysisRevision
    fun acquire(target: TlsKeyLogImportTarget, parsed: KeyLogParseResult.Success,
                checkCancelled: () -> Unit): TlsAnalysisSecretLease
    /** Ownership transfers on entry, including cancellation and failure. */
    suspend fun configure(target: TlsKeyLogImportTarget, lease: TlsAnalysisSecretLease?,
                          progress: (Int, Int) -> Unit): TlsAnalysisResult
}

/** Main-thread actions; blocking parsing/storage runs on IO, with guarded progress publication. */
internal class TlsKeyLogImportController(
    private val scope: CoroutineScope,
    private val backend: TlsKeyLogImportBackend,
    private val io: CoroutineDispatcher = Dispatchers.IO
) {
    private val mutableState = MutableStateFlow(TlsKeyLogImportState())
    val state = mutableState.asStateFlow()
    private var selectedTarget: TlsKeyLogImportTarget? = null
    private var job: Job? = null
    @Volatile private var operation = 0L
    private var lastObservation: CaptureAnalysisRevision? = null
    /** The revision's totals, kept with it so both are dropped together. */
    private var lastPlaintext: TlsPlaintextStats = TlsPlaintextStats.EMPTY
    private val pendingCleanup = ConcurrentHashMap.newKeySet<TlsAnalysisSecretLease>()

    fun beginSelection(): Boolean {
        if (state.value.busy || job?.isActive == true) return false
        val target = backend.currentTarget() ?: return false
        selectedTarget = target
        mutableState.value = state.value.copy(phase = TlsKeyLogImportPhase.Selecting,
            errorCode = null, parseError = null, cancelled = false, reopenRequired = false)
        return true
    }

    fun selected(open: (() -> InputStream)?) {
        val target = selectedTarget ?: return
        selectedTarget = null
        if (open == null) {
            mutableState.value = state.value.copy(phase = TlsKeyLogImportPhase.Idle)
            return
        }
        if (backend.currentTarget() != target) {
            mutableState.value = state.value.copy(phase = TlsKeyLogImportPhase.Idle, errorCode = "STALE_GENERATION")
            syncAnalysis(backend.currentAnalysis())
            return
        }
        start(target, open)
    }

    fun clear() {
        if (state.value.busy || job?.isActive == true) return
        val target = backend.currentTarget() ?: return
        start(target, null)
    }

    fun cancel() {
        if (state.value.phase == TlsKeyLogImportPhase.Selecting) {
            selectedTarget = null
            mutableState.value = state.value.copy(phase = TlsKeyLogImportPhase.Idle)
        } else if (job?.isActive == true) {
            mutableState.value = state.value.copy(phase = TlsKeyLogImportPhase.Cancelling)
            job?.cancel()
        }
    }

    /** Called before a file switch/close. Late SAF responses and IO callbacks cannot target B. */
    fun invalidate() {
        operation++
        selectedTarget = null
        job?.cancel()
        lastObservation = null
        lastPlaintext = TlsPlaintextStats.EMPTY
        mutableState.value = TlsKeyLogImportState()
    }

    fun syncAnalysis(revision: CaptureAnalysisRevision) {
        val current = revision.ready && revision == lastObservation
        mutableState.update { it.copy(
            configured = revision.ready && revision.configured,
            observedDecryptedData = current,
            // Counts are only as current as the verdict they belong to.
            plaintextStats = if (current) lastPlaintext else TlsPlaintextStats.EMPTY) }
    }

    /**
     * Records the analysis-side plaintext observation of [revision].
     *
     * Opening a capture that already holds retained secrets configures native inside the
     * coordinator transaction, not through [start], so that path has no job result to
     * publish. Without this entry point the page could never report an observation for a
     * plainly opened capture even when the analyser did decrypt application data.
     * Only the current ready revision may claim plaintext; anything else is dropped and
     * the published state is resynchronised from the authoritative revision.
     */
    fun recordObservation(revision: CaptureAnalysisRevision, plaintext: TlsPlaintextStats) {
        val current = backend.currentAnalysis()
        if (revision.ready && revision == current) {
            lastObservation = revision.takeIf { plaintext.observed }
            lastPlaintext = plaintext.takeIf { plaintext.observed } ?: TlsPlaintextStats.EMPTY
        }
        syncAnalysis(current)
    }

    private fun start(target: TlsKeyLogImportTarget, open: (() -> InputStream)?) {
        val request = ++operation
        mutableState.value = state.value.copy(
            phase = if (open == null) TlsKeyLogImportPhase.Redissection else TlsKeyLogImportPhase.Reading,
            parseError = null, errorCode = null, cancelled = false, reopenRequired = false,
            processedFrames = 0, totalFrames = 0)
        job = scope.launch {
            var pendingLease: TlsAnalysisSecretLease? = null
            var parsed: KeyLogParseResult.Success? = null
            val caller = currentCoroutineContext()
            fun checkCurrent() {
                caller.ensureActive()
                if (operation != request || backend.currentTarget() != target) throw StaleCaptureAnalysisException()
            }
            fun publish(transform: (TlsKeyLogImportState) -> TlsKeyLogImportState) {
                mutableState.update { if (operation == request) transform(it) else it }
            }
            try {
                withContext(NonCancellable + io) {
                    pendingCleanup.toList().forEach { lease ->
                        lease.close()
                        pendingCleanup.remove(lease)
                    }
                }
                if (open != null) {
                    // A returned lease must not be lost to withContext's prompt cancellation.
                    withContext(NonCancellable + io) {
                        checkCurrent()
                        val result = open().use { input ->
                            val checked = object : FilterInputStream(input) {
                                override fun read(): Int { checkCurrent(); return input.read() }
                                override fun read(bytes: ByteArray, offset: Int, length: Int): Int {
                                    checkCurrent(); return input.read(bytes, offset, length)
                                }
                            }
                            KeyLogParser.parse(checked)
                        }
                        checkCurrent()
                        when (result) {
                            is KeyLogParseResult.Failure -> publish { it.copy(parseError = result.error) }
                            is KeyLogParseResult.Success -> {
                                parsed = result
                                publish { it.copy(phase = TlsKeyLogImportPhase.Saving) }
                                pendingLease = backend.acquire(target, result, ::checkCurrent)
                            }
                        }
                    }
                    checkCurrent()
                    if (parsed == null) return@launch
                }
                checkCurrent()
                publish { it.copy(phase = TlsKeyLogImportPhase.Redissection) }
                val transferred = pendingLease
                pendingLease = null
                var lastProgressNanos = 0L
                val result = backend.configure(target, transferred) { done, total ->
                    val now = System.nanoTime()
                    if (done == 0 || done == total || now - lastProgressNanos >= 250_000_000L) {
                        lastProgressNanos = now
                        publish { it.copy(processedFrames = done, totalFrames = total) }
                    }
                }
                if (operation != request) return@launch
                val current = backend.currentAnalysis()
                if (result.success && current == result.analysis && current.ready) {
                    lastObservation = current.takeIf { result.observedDecryptedData }
                    lastPlaintext = result.plaintextStats.takeIf { result.observedDecryptedData }
                        ?: TlsPlaintextStats.EMPTY
                    publish { it.copy(configured = current.configured,
                        observedDecryptedData = result.observedDecryptedData,
                        plaintextStats = lastPlaintext,
                        importedRecords = parsed?.records?.size ?: 0,
                        duplicateLines = parsed?.stats?.duplicateLines ?: 0,
                        unsupportedLines = parsed?.stats?.unsupportedLines ?: 0) }
                } else publish { it.copy(errorCode = safeNativeCode(result.errorCode),
                    reopenRequired = result.reopenRequired) }
            } catch (_: CancellationException) {
                publish { it.copy(cancelled = true, reopenRequired = backend.currentAnalysis().sessionHandle == 0L) }
            } catch (error: Exception) {
                publish { it.copy(errorCode = (error as? TlsAssetException)?.code?.name ?: "IO_ERROR") }
            } catch (_: LinkageError) {
                publish { it.copy(errorCode = "UNSUPPORTED") }
            } finally {
                // Keep both cleanup and the return to the UI dispatcher non-cancellable.
                // NonCancellable + io alone can throw prompt cancellation on return,
                // leaving a finished operation permanently in Cancelling/Reading.
                withContext(NonCancellable) {
                    withContext(io) {
                        try { pendingLease?.close() } catch (_: Exception) {
                            pendingLease?.let(pendingCleanup::add)
                            publish { it.copy(errorCode = "NATIVE_CLEANUP_FAILED") }
                        }
                    }
                    if (operation == request) {
                        syncAnalysis(backend.currentAnalysis())
                        publish { it.copy(phase = TlsKeyLogImportPhase.Idle) }
                    }
                }
            }
        }
    }

    private fun safeNativeCode(code: String?): String =
        TlsErrorCode.fromWire(code ?: "UNKNOWN").wireName
}
