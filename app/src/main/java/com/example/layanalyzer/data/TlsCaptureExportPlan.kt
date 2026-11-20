// Copyright (c) 2026 cheig; GPL-3.0.
package com.example.layanalyzer.data

import com.example.layanalyzer.capture.tls.TlsSecretAssetRef
import com.example.layanalyzer.capture.tls.KeyLogParser

/** Plaintext is exported by the existing selected stream/object/bytes actions. */
enum class TlsCaptureExportKind { OriginalCapture, CompleteDecryptableSession, SelectedPlaintext }

enum class TlsCaptureExportFailure { FILTERED_SECRETS, CONFIRMATION_REQUIRED, CAPTURE_INCOMPLETE, SECRETS_UNAVAILABLE }

class TlsCaptureExportException(val reason: TlsCaptureExportFailure) :
    IllegalStateException(reason.name)

object TlsCaptureExportPlan {
    val defaultKind = TlsCaptureExportKind.OriginalCapture

    /** A filter never authorizes releasing connection-wide secrets. No file I/O or UI state. */
    fun requireCompleteSession(
        filtered: Boolean,
        confirmed: Boolean,
        state: CaptureArtifactState?,
        asset: TlsSecretAssetRef?
    ): CaptureArtifactState.Present {
        fun reject(reason: TlsCaptureExportFailure): Nothing = throw TlsCaptureExportException(reason)
        if (filtered) reject(TlsCaptureExportFailure.FILTERED_SECRETS)
        if (!confirmed) reject(TlsCaptureExportFailure.CONFIRMATION_REQUIRED)
        val present = state as? CaptureArtifactState.Present
            ?: reject(TlsCaptureExportFailure.CAPTURE_INCOMPLETE)
        val manifest = present.manifest
        if (!present.isComplete || manifest.packetDrops != 0L || manifest.segments.isEmpty()) {
            reject(TlsCaptureExportFailure.CAPTURE_INCOMPLETE)
        }
        if (!manifest.decryptionIsComplete || asset == null || asset.captureId != present.captureId ||
            asset.assetId != manifest.tls.secretsAssetId ||
            asset.watermark.sequence != manifest.secretsPersistedSequence || asset.watermark.sequence < 1L ||
            asset.keyLogBytes !in 1..KeyLogParser.MAX_TOTAL_BYTES || manifest.tls.keylogFormat != "NSS"
        ) reject(TlsCaptureExportFailure.SECRETS_UNAVAILABLE)
        return present
    }
}
