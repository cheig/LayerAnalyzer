// Copyright (c) 2026 cheig
// LayerAnalyzer - https://github.com/cheig/LayerAnalyzer
// Licensed under GNU GPL version 3; see LICENSE.

package com.example.layanalyzer.model

/**
 * The persisted description of one capture's assets (design §8.3, contract C08).
 *
 * The manifest is metadata only: it never carries a keylog line, a private key, a
 * token or an absolute path to a secret. Segment entries are relative to the
 * capture directory, and the location of every asset is derived from the local
 * [captureId], never from a path an imported JSON file supplied.
 *
 * [captureIsComplete] and [decryptionIsComplete] are deliberately separate:
 * a byte-complete PCAP says nothing about whether its TLS secrets were retained,
 * and a retained keylog never turns a truncated capture into a complete one.
 * Whole values are immutable; the repository owns reading and writing.
 */
data class CaptureArtifactManifest(
    val captureId: String,
    val schemaVersion: Int = SCHEMA_VERSION,
    val captureMode: CaptureMode = CaptureMode.VpnCapture,
    val packetVantage: PacketVantage = PacketVantage.TunInterface,
    val segments: List<CaptureSegmentRef> = emptyList(),
    val packetDrops: Long = 0L,
    val interrupted: Boolean = false,
    /** Analysis revision this manifest was written against (0 = never analyzed). */
    val dissectionGeneration: Long = 0L,
    /** Secrets watermark actually committed to disk, not an accepted count. */
    val secretsPersistedSequence: Long = 0L,
    val retentionPolicy: CaptureRetentionPolicy = CaptureRetentionPolicy.KeepCaptureAndSecrets,
    /** Zero while unfinalized; set to the commit wall-clock time when finalized. */
    val finalizedAtMillis: Long = 0L,
    val tls: CaptureTlsAssets = CaptureTlsAssets(),
    /** True only after an atomic commit replaced the manifest with a complete one. */
    val finalized: Boolean = false,
    /** Capture-level completeness: writers drained, nothing dropped, not interrupted. */
    val complete: Boolean = false
) {
    /** No PCAP truncation, drop or interruption; independent of the secrets side. */
    val captureIsComplete: Boolean get() = finalized && complete && !interrupted

    /** Secrets were retained for this capture; independent of PCAP completeness. */
    val decryptionIsComplete: Boolean get() = tls.enabled && tls.complete

    companion object {
        const val SCHEMA_VERSION = 1
    }
}

/** One PCAP segment. [file] is a relative, forward-slash path inside the capture dir. */
data class CaptureSegmentRef(
    val file: String,
    /** 1-based global frame number of this segment's first persisted frame. */
    val firstGlobalFrame: Long,
    /** Persisted frames in this segment; offered-but-unwritten packets are excluded. */
    val frameCount: Long,
    val lengthBytes: Long = 0L,
    /** Lowercase hex SHA-256 of the segment file, or blank while unfinalized. */
    val segmentSha256: String = "",
    val finalized: Boolean = false
) {
    val lastGlobalFrame: Long get() = firstGlobalFrame + frameCount - 1L
}

/** The TLS half of a capture's assets. Absent/disabled is the honest default. */
data class CaptureTlsAssets(
    val enabled: Boolean = false,
    val caFingerprintSha256: String? = null,
    val secretsAssetId: String? = null,
    val keylogFormat: String = "NSS",
    val secretsGeneration: Long = 0L,
    /** Only true when every accepted secret reached the disk (C05 watermark). */
    val complete: Boolean = false
)

/** How the packets were observed. Explicit wire strings; never Kotlin ordinals (C04). */
enum class CaptureMode(val wireName: String) {
    VpnCapture("vpn_capture"),
    ActiveTlsProxy("active_tls_proxy");

    companion object {
        fun fromWire(value: String?): CaptureMode? = entries.firstOrNull { it.wireName == value }
    }
}

/** Where in the path the packets were captured. Explicit wire strings (C04). */
enum class PacketVantage(val wireName: String) {
    TunInterface("tun_interface"),
    AppToLocalProxy("app_to_local_proxy");

    companion object {
        fun fromWire(value: String?): PacketVantage? = entries.firstOrNull { it.wireName == value }
    }
}

/**
 * Local retention intent, recorded so TLS-312 can purge consistently. The name is
 * metadata; it does not by itself delete anything here.
 */
enum class CaptureRetentionPolicy(val wireName: String) {
    /** Keep the PCAP and the encrypted secrets so the capture reopens decryptable. */
    KeepCaptureAndSecrets("keep_capture_and_secrets"),
    /** Keep the PCAP but secrets are transient (retainSecrets=false, C08). */
    KeepCaptureTransientSecrets("keep_capture_transient_secrets");

    companion object {
        fun fromWire(value: String?): CaptureRetentionPolicy? = entries.firstOrNull { it.wireName == value }
    }
}

/**
 * Inputs [com.example.layanalyzer.capture.LiveCaptureStore] needs from a caller to
 * write a manifest. Passing none keeps the legacy behaviour (no manifest at all).
 */
data class LiveCaptureManifestConfig(
    val captureId: String,
    val captureMode: CaptureMode = CaptureMode.VpnCapture,
    val packetVantage: PacketVantage = PacketVantage.TunInterface,
    val retentionPolicy: CaptureRetentionPolicy = CaptureRetentionPolicy.KeepCaptureAndSecrets,
    val tls: CaptureTlsAssets = CaptureTlsAssets()
)
