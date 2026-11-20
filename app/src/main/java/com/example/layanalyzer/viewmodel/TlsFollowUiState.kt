// Copyright (c) 2026 cheig; GPL-3.0.
package com.example.layanalyzer.viewmodel

import com.example.layanalyzer.model.PacketTlsFollowAction
import com.example.layanalyzer.model.TLS_FOLLOW_PREVIEW_LIMIT
import com.example.layanalyzer.model.TlsErrorCode
import com.example.layanalyzer.model.TlsFollowDirection
import com.example.layanalyzer.model.TlsFollowExportResult
import com.example.layanalyzer.model.TlsFollowRecord
import com.example.layanalyzer.model.TlsFollowResult
import com.example.layanalyzer.model.TlsFollowScope
import com.example.layanalyzer.model.TlsFollowUnavailableReason

/** Presentation formats for the TLS follow viewer. The TCP/UDP screen keeps its own enum. */
enum class TlsFollowFormat { Utf8, Ascii, Hex }

enum class TlsFollowDirectionFilter { Both, Client, Server }

/**
 * Why the context-menu "Follow TLS stream" item cannot run. Localized by the UI layer; kept here so
 * "no key", "unknown direction", "missing packets" and "session switch" are explicit, non-diagnostic
 * prompts rather than a silent disabled item.
 */
enum class TlsFollowPrompt {
    Loading,
    NotTls,
    SecretsNotConfigured,
    HandshakeIncomplete,
    NoDecryptedApplicationData,
    Stale,
    Unavailable,
    Failed
}

/** Honest limitations of a loaded preview, never collapsed into a "complete" claim. */
data class TlsFollowBanner(
    val scope: TlsFollowScope,
    val directionKnown: Boolean,
    val truncated: Boolean,
    val incomplete: Boolean,
    val available: Boolean,
    val unavailableReason: TlsFollowUnavailableReason?
)

/** Outcome of a bounded full-stream export. Cancellation is never a success. */
sealed interface TlsFollowExportOutcome {
    data class Success(
        val byteLength: Long,
        val sha256: String,
        val truncated: Boolean,
        val incomplete: Boolean,
        val directionKnown: Boolean
    ) : TlsFollowExportOutcome

    data class Failed(val errorCode: TlsErrorCode) : TlsFollowExportOutcome

    data object Cancelled : TlsFollowExportOutcome
}

/** TLS-308 viewer state: the frame and its bounded preview result. Render choices stay local to the UI. */
data class TlsFollowViewerState(
    val frameNumber: Long,
    val result: TlsFollowResult
)

/**
 * TLS-308 pure presentation logic for the TLS follow viewer and its bounded export. It never holds
 * or copies a full stream: the preview is already bounded to [TLS_FOLLOW_PREVIEW_LIMIT], and the
 * larger export goes through the native streaming file writer instead of a bigger JSON budget.
 */
object TlsFollowUiState {
    val previewLimit: Int get() = TLS_FOLLOW_PREVIEW_LIMIT

    /** Null means the action is runnable; otherwise the reason to show in the context menu. */
    fun promptFor(action: PacketTlsFollowAction): TlsFollowPrompt? {
        if (action.enabled) return null
        if (action.isLoading) return TlsFollowPrompt.Loading
        action.unavailableReason?.let { reason ->
            return when (reason) {
                TlsFollowUnavailableReason.NotTls -> TlsFollowPrompt.NotTls
                TlsFollowUnavailableReason.SecretsNotConfigured -> TlsFollowPrompt.SecretsNotConfigured
                TlsFollowUnavailableReason.HandshakeIncomplete -> TlsFollowPrompt.HandshakeIncomplete
                TlsFollowUnavailableReason.NoDecryptedApplicationData ->
                    TlsFollowPrompt.NoDecryptedApplicationData
                TlsFollowUnavailableReason.Unknown -> TlsFollowPrompt.Unavailable
            }
        }
        return when (action.errorCode) {
            TlsErrorCode.STALE_GENERATION -> TlsFollowPrompt.Stale
            TlsErrorCode.NOT_READY, TlsErrorCode.CANCELLED, null -> TlsFollowPrompt.Unavailable
            else -> TlsFollowPrompt.Failed
        }
    }

    fun banner(result: TlsFollowResult): TlsFollowBanner = TlsFollowBanner(
        scope = result.scope,
        directionKnown = result.directionKnown,
        truncated = result.truncated,
        incomplete = result.incomplete,
        available = result.success && result.records.isNotEmpty(),
        unavailableReason = result.unavailableReason
    )

    /**
     * Select the records to render. The query is matched against the currently rendered format, and
     * a format switch re-renders the already-held, bounded preview instead of re-reading the stream.
     */
    fun filter(
        records: List<TlsFollowRecord>,
        direction: TlsFollowDirectionFilter,
        query: String,
        format: TlsFollowFormat
    ): List<TlsFollowRecord> = records.filter { record ->
        direction.matches(record.direction) &&
            (query.isBlank() || format(record.bytes, format).contains(query, ignoreCase = true))
    }

    /** Renders one bounded record in the requested format. Pure: the byte array is never modified. */
    fun format(bytes: ByteArray, format: TlsFollowFormat): String = when (format) {
        TlsFollowFormat.Utf8 -> String(bytes, Charsets.UTF_8)
        TlsFollowFormat.Ascii -> buildString(bytes.size) {
            bytes.forEach { value ->
                val byte = value.toInt() and 0xff
                append(if (byte in 32..126) byte.toChar() else '.')
            }
        }
        TlsFollowFormat.Hex -> buildString(bytes.size * 3) {
            bytes.forEachIndexed { index, value ->
                if (index > 0) append(' ')
                val byte = value.toInt() and 0xff
                append(HEX_DIGITS[byte ushr 4])
                append(HEX_DIGITS[byte and 0x0f])
            }
        }
    }

    /**
     * A failed or cancelled export is never a success: only a reported success with a digest becomes
     * [TlsFollowExportOutcome.Success]. The caller removes the file on anything else.
     */
    fun exportOutcome(result: TlsFollowExportResult): TlsFollowExportOutcome {
        if (result.success) {
            val digest = result.sha256
            return if (digest == null || result.byteLength <= 0L) {
                TlsFollowExportOutcome.Failed(TlsErrorCode.UNKNOWN)
            } else {
                TlsFollowExportOutcome.Success(result.byteLength, digest, result.truncated,
                    result.incomplete, result.directionKnown)
            }
        }
        return when (result.errorCode) {
            TlsErrorCode.CANCELLED -> TlsFollowExportOutcome.Cancelled
            null -> TlsFollowExportOutcome.Failed(TlsErrorCode.UNKNOWN)
            else -> TlsFollowExportOutcome.Failed(result.errorCode)
        }
    }

    fun defaultExportFileName(frameNumber: Long, streamId: Int?): String =
        "tls-stream-${streamId ?: frameNumber}-$frameNumber.bin"

    private fun TlsFollowDirectionFilter.matches(direction: TlsFollowDirection) = when (this) {
        TlsFollowDirectionFilter.Both -> true
        TlsFollowDirectionFilter.Client -> direction == TlsFollowDirection.Client
        TlsFollowDirectionFilter.Server -> direction == TlsFollowDirection.Server
    }

    private val HEX_DIGITS = "0123456789ABCDEF".toCharArray()
}
