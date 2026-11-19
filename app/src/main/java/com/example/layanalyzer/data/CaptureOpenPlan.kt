// Copyright (c) 2026 cheig
// LayerAnalyzer - https://github.com/cheig/LayerAnalyzer
// Licensed under GNU GPL version 3; see LICENSE.

package com.example.layanalyzer.data

import com.example.layanalyzer.capture.tls.TlsAssetErrorCode
import com.example.layanalyzer.capture.tls.TlsAssetIdentity
import com.example.layanalyzer.model.CaptureArtifactManifest
import com.example.layanalyzer.model.CaptureMode
import com.example.layanalyzer.model.CaptureRetentionPolicy
import com.example.layanalyzer.model.PacketVantage
import java.io.File

/**
 * Which input a saved capture's analysis session is opened from (TLS-310, design §8.5).
 *
 * [WholeCapture] is the merged file of every manifest segment; [SingleSegment] is a
 * deliberate one-segment subset (disk-full fallback) that must never be presented as
 * the whole capture; [LegacySingleFile] is the pre-manifest layout, whose one PCAP is
 * already whole.
 */
enum class CaptureOpenScope { WholeCapture, SingleSegment, LegacySingleFile }

/**
 * What the open chain found for this capture's retained secrets, resolved only through
 * the manifest and the `noBackupFilesDir/capture-secrets/<captureId>` asset path (C08).
 * A [LegacySingleFile] capture has no manifest and therefore never resolves secrets.
 */
sealed interface CaptureOpenSecrets {
    /** A manifest named this asset and it is still the capture's current one. */
    data class Available(val assetId: String) : CaptureOpenSecrets

    /** Nothing to load: no manifest, TLS disabled, or the manifest names no secret. */
    data object Absent : CaptureOpenSecrets

    /** The secrets store refused (capacity, I/O, format); the capture still opens. */
    data class Unavailable(val code: TlsAssetErrorCode) : CaptureOpenSecrets
}

/** Honest degradations the open chain must surface instead of hiding (C03 7). */
enum class CaptureOpenNotice {
    MISSING_SEGMENT,
    TRUNCATED_SEGMENT,
    UNFINISHED_SEGMENT,
    UNREADABLE_SEGMENT,
    FRAME_COUNT_MISMATCH,
    SEGMENT_LENGTH_MISMATCH,
    SEGMENT_HASH_MISMATCH,
    SINGLE_SEGMENT_FALLBACK,
    DISK_FULL_FALLBACK,
    PACKETS_DROPPED,
    CAPTURE_INTERRUPTED,
    SECRETS_ABSENT,
    SECRETS_UNAVAILABLE,
    SECRETS_INCOMPLETE
}

/** A fixed reason a saved capture cannot be opened at all; never a raw exception. */
enum class CaptureOpenFailure { NOT_FOUND, CORRUPT, NO_SPACE, IO_ERROR }

/**
 * The stages an open chain releases on failure or cancel, in the order it must release
 * them. Acquisition is the reverse: the derived merged file is created first, then the
 * secret lease, then the native key configuration; teardown therefore unwinds native
 * first, the lease second and the derived file last.
 */
enum class CaptureOpenTeardown { NativeSecrets, SecretLease, DerivedAnalysisFile }

/**
 * The resolved, executable decision for one saved capture (TLS-310).
 *
 * It is a value, not an action: [CaptureOpenPlanner.plan] derives it from the repository
 * facts and the executor only follows it, so every branch (whole capture, single-segment
 * fallback, legacy, unavailable, cancelled) is host-testable without a device.
 */
sealed interface CaptureOpenPlan {
    val captureId: String

    data class Open(
        override val captureId: String,
        /** The PCAP the analysis session opens: the merged file, or the legacy file itself. */
        val analysisFile: File,
        val scope: CaptureOpenScope,
        /** Non-null only when a real secret lease must be acquired and configured. */
        val secretAssetId: String?,
        val contextIncomplete: Boolean,
        val notices: List<CaptureOpenNotice>,
        /** Frames in [analysisFile]; 0 for a legacy file whose count is only known after opening. */
        val totalFrames: Long,
        val byteLength: Long,
        val packetDrops: Long,
        val captureComplete: Boolean,
        val decryptionComplete: Boolean,
        val retention: CaptureRetentionPolicy,
        val captureMode: CaptureMode,
        val vantage: PacketVantage
    ) : CaptureOpenPlan {
        val requiresSecretLease: Boolean get() = secretAssetId != null

        /**
         * The only artefact this chain owns and may delete on teardown. A legacy capture's
         * file is the user's original PCAP, so it is deliberately never returned here.
         */
        val derivedAnalysisFile: File?
            get() = if (scope == CaptureOpenScope.LegacySingleFile) null else analysisFile

        /** True when the frame set shown cannot be the whole capture (TLS-302's rule). */
        val singleSegmentOnly: Boolean get() = scope == CaptureOpenScope.SingleSegment
    }

    data class Unavailable(
        override val captureId: String,
        val failure: CaptureOpenFailure,
        /** A segment the caller could open alone instead, when the whole merge cannot run. */
        val fallbackSegment: String? = null
    ) : CaptureOpenPlan

    data class Cancelled(override val captureId: String) : CaptureOpenPlan
}

/**
 * The facts the UI shows about a completed saved-capture open (TLS-310 step 2): the whole
 * capture range, drops, secret completeness and the packet vantage. It carries no secret
 * material and no absolute secret path (C03 6), only counts, fixed enums and a rendered
 * message.
 */
data class SavedCaptureOpenInfo(
    val captureId: String,
    val message: String,
    val scope: CaptureOpenScope,
    val totalFrames: Long,
    val packetDrops: Long,
    val decryptionComplete: Boolean,
    val contextIncomplete: Boolean,
    val captureMode: CaptureMode,
    val vantage: PacketVantage,
    val notices: List<CaptureOpenNotice>
)

/**
 * Derives a [CaptureOpenPlan] from a capture's resolved assets (TLS-310, C08).
 *
 * The one rule that must not bend: secrets are resolved exclusively through the manifest
 * and the capture's own `capture-secrets/<captureId>` asset, never by scanning for a
 * keylog next to the PCAP. A [CaptureAnalysisSource.Legacy] capture has no manifest, so it
 * opens with [CaptureOpenSecrets.Absent] no matter what sits beside it.
 */
object CaptureOpenPlanner {
    /** Reverse-of-acquisition teardown order; see [CaptureOpenTeardown]. */
    val TEARDOWN_ORDER: List<CaptureOpenTeardown> = listOf(
        CaptureOpenTeardown.NativeSecrets,
        CaptureOpenTeardown.SecretLease,
        CaptureOpenTeardown.DerivedAnalysisFile
    )

    /**
     * The capture id a saved capture file belongs to. The capture service names the file
     * `<captureId>.pcap`, so the id is the file's base name; anything that is not a valid
     * local id (C08) has no manifest to look up and returns null.
     */
    fun captureIdFor(savedCapture: File): String? {
        val name = savedCapture.name
        val candidate = if (name.length > PCAP_EXTENSION.length && name.endsWith(PCAP_EXTENSION, ignoreCase = true)) {
            name.dropLast(PCAP_EXTENSION.length)
        } else {
            name
        }
        return candidate.takeIf { TlsAssetIdentity.validId(it) }
    }

    /** Maps a store error code onto the fixed open failure vocabulary. */
    fun failureFor(code: TlsAssetErrorCode): CaptureOpenFailure = when (code) {
        TlsAssetErrorCode.NOT_FOUND -> CaptureOpenFailure.NOT_FOUND
        TlsAssetErrorCode.DISK_FULL -> CaptureOpenFailure.NO_SPACE
        TlsAssetErrorCode.INVALID_FORMAT,
        TlsAssetErrorCode.UNSUPPORTED_VERSION,
        TlsAssetErrorCode.BINDING_MISMATCH,
        TlsAssetErrorCode.AUTHENTICATION_FAILED,
        TlsAssetErrorCode.INVALID_SEQUENCE,
        TlsAssetErrorCode.NONCE_REUSED,
        TlsAssetErrorCode.TRUNCATED_TAIL -> CaptureOpenFailure.CORRUPT
        else -> CaptureOpenFailure.IO_ERROR
    }

    /**
     * Decides what the open chain may do with this capture's secrets, from the manifest
     * and the store facts only (C08). It never consults the filesystem for a keylog beside
     * the PCAP: a legacy capture, a manifest without TLS, or a manifest naming an asset the
     * capture no longer has resolves to [CaptureOpenSecrets.Absent]. A store error is
     * surfaced as [CaptureOpenSecrets.Unavailable] so the capture still opens undecrypted.
     */
    fun resolveSecrets(
        manifest: CaptureArtifactManifest?,
        source: CaptureAnalysisSource,
        expectedAssetId: String?,
        currentAssetId: String?,
        storeError: TlsAssetErrorCode? = null
    ): CaptureOpenSecrets {
        if (storeError != null) return CaptureOpenSecrets.Unavailable(storeError)
        if (manifest == null || !manifest.tls.enabled) return CaptureOpenSecrets.Absent
        if (source !is CaptureAnalysisSource.Merged) return CaptureOpenSecrets.Absent
        if (expectedAssetId == null || currentAssetId == null || currentAssetId != expectedAssetId) {
            return CaptureOpenSecrets.Absent
        }
        return CaptureOpenSecrets.Available(expectedAssetId)
    }

    /**
     * The plan for one resolved capture. [manifest] is the parsed manifest, or null for a
     * legacy capture; [extraNotices] carries decisions made before this call (the disk-full
     * single-segment fallback).
     */
    fun plan(
        captureId: String,
        source: CaptureAnalysisSource,
        secrets: CaptureOpenSecrets,
        manifest: CaptureArtifactManifest? = null,
        extraNotices: List<CaptureOpenNotice> = emptyList()
    ): CaptureOpenPlan = when (source) {
        is CaptureAnalysisSource.Merged -> planMerged(captureId, source, secrets, manifest, extraNotices)
        is CaptureAnalysisSource.Legacy -> CaptureOpenPlan.Open(
            captureId = captureId,
            analysisFile = source.captureFile,
            scope = CaptureOpenScope.LegacySingleFile,
            // C08: no manifest, so never a keylog — even if one is sitting right there.
            secretAssetId = null,
            contextIncomplete = false,
            notices = emptyList(),
            totalFrames = 0L,
            byteLength = source.captureFile.length(),
            packetDrops = 0L,
            captureComplete = false,
            decryptionComplete = false,
            retention = CaptureRetentionPolicy.KeepCaptureAndSecrets,
            captureMode = CaptureMode.VpnCapture,
            vantage = PacketVantage.TunInterface
        )
        is CaptureAnalysisSource.Missing ->
            CaptureOpenPlan.Unavailable(captureId, CaptureOpenFailure.NOT_FOUND)
        is CaptureAnalysisSource.Refused ->
            CaptureOpenPlan.Unavailable(captureId, failureFor(source.reason))
        is CaptureAnalysisSource.Cancelled ->
            CaptureOpenPlan.Cancelled(captureId)
    }

    /** The single-segment plan the caller builds when the whole merge cannot run. */
    fun singleSegmentFallback(
        captureId: String,
        source: CaptureAnalysisSource,
        secrets: CaptureOpenSecrets,
        manifest: CaptureArtifactManifest
    ): CaptureOpenPlan = plan(
        captureId = captureId,
        source = source,
        secrets = secrets,
        manifest = manifest,
        extraNotices = listOf(CaptureOpenNotice.DISK_FULL_FALLBACK)
    )

    private fun planMerged(
        captureId: String,
        source: CaptureAnalysisSource.Merged,
        secrets: CaptureOpenSecrets,
        manifest: CaptureArtifactManifest?,
        extraNotices: List<CaptureOpenNotice>
    ): CaptureOpenPlan.Open {
        val notices = LinkedHashSet<CaptureOpenNotice>()
        source.issues.forEach { notices += noticeFor(source = it.kind) }
        source.manifestIssues.forEach { notices += noticeFor(issue = it) }
        if (source.singleSegment) notices += CaptureOpenNotice.SINGLE_SEGMENT_FALLBACK
        notices += extraNotices

        val tlsEnabled = manifest?.tls?.enabled == true
        // A lease is only ever requested for a manifest-backed capture whose TLS block is
        // enabled and whose manifest still names the current secrets asset.
        val secretAssetId = (secrets as? CaptureOpenSecrets.Available)?.assetId?.takeIf { tlsEnabled }

        if (tlsEnabled) {
            when (secrets) {
                is CaptureOpenSecrets.Available ->
                    if (manifest?.tls?.complete != true) notices += CaptureOpenNotice.SECRETS_INCOMPLETE
                CaptureOpenSecrets.Absent -> notices += CaptureOpenNotice.SECRETS_ABSENT
                is CaptureOpenSecrets.Unavailable -> notices += CaptureOpenNotice.SECRETS_UNAVAILABLE
            }
        }
        val drops = manifest?.packetDrops ?: 0L
        if (drops > 0L) notices += CaptureOpenNotice.PACKETS_DROPPED
        if (manifest?.interrupted == true) notices += CaptureOpenNotice.CAPTURE_INTERRUPTED

        val captureComplete = source.captureIsComplete && manifest?.captureIsComplete != false
        val decryptionComplete = secretAssetId != null && manifest?.decryptionIsComplete == true

        return CaptureOpenPlan.Open(
            captureId = captureId,
            analysisFile = source.analysisFile,
            scope = if (source.singleSegment) CaptureOpenScope.SingleSegment else CaptureOpenScope.WholeCapture,
            secretAssetId = secretAssetId,
            contextIncomplete = source.contextIncomplete,
            notices = notices.toList(),
            totalFrames = source.totalFrames,
            byteLength = source.byteLength,
            packetDrops = drops,
            captureComplete = captureComplete,
            decryptionComplete = decryptionComplete,
            retention = manifest?.retentionPolicy ?: CaptureRetentionPolicy.KeepCaptureAndSecrets,
            captureMode = manifest?.captureMode ?: CaptureMode.VpnCapture,
            vantage = manifest?.packetVantage ?: PacketVantage.TunInterface
        )
    }

    private fun noticeFor(source: CaptureMergeIssueKind): CaptureOpenNotice = when (source) {
        CaptureMergeIssueKind.SEGMENT_NOT_FINALIZED -> CaptureOpenNotice.UNFINISHED_SEGMENT
        CaptureMergeIssueKind.SEGMENT_FILE_MISSING -> CaptureOpenNotice.MISSING_SEGMENT
        CaptureMergeIssueKind.SEGMENT_UNREADABLE -> CaptureOpenNotice.UNREADABLE_SEGMENT
        CaptureMergeIssueKind.SEGMENT_TRUNCATED_TAIL -> CaptureOpenNotice.TRUNCATED_SEGMENT
        CaptureMergeIssueKind.SEGMENT_FRAME_COUNT_MISMATCH -> CaptureOpenNotice.FRAME_COUNT_MISMATCH
    }

    private fun noticeFor(issue: CaptureSegmentIssue): CaptureOpenNotice = when (issue) {
        CaptureSegmentIssue.SEGMENT_NOT_FINALIZED -> CaptureOpenNotice.UNFINISHED_SEGMENT
        CaptureSegmentIssue.SEGMENT_FILE_MISSING -> CaptureOpenNotice.MISSING_SEGMENT
        CaptureSegmentIssue.SEGMENT_LENGTH_MISMATCH -> CaptureOpenNotice.SEGMENT_LENGTH_MISMATCH
        CaptureSegmentIssue.SEGMENT_HASH_MISMATCH -> CaptureOpenNotice.SEGMENT_HASH_MISMATCH
    }

    private const val PCAP_EXTENSION = ".pcap"
}
