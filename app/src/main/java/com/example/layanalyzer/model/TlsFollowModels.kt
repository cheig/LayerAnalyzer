// Copyright (c) 2026 cheig; GPL-3.0.
package com.example.layanalyzer.model

const val TLS_FOLLOW_PREVIEW_LIMIT = 1024 * 1024
const val TLS_FOLLOW_RECORD_LIMIT = 8192

/**
 * TLS-308 full-stream export cap. The preview stays at [TLS_FOLLOW_PREVIEW_LIMIT]; this only bounds
 * the separate streaming-to-file path, which never copies the stream into memory. 64 MiB is far
 * larger than the 1 MiB preview while still bounding a single connection's export, and the result
 * reports truncation honestly instead of silently stopping.
 */
const val TLS_FOLLOW_EXPORT_LIMIT = 64 * 1024 * 1024

enum class TlsFollowScope(val wireName: String) {
    CompleteConnection("complete_connection")
}

enum class TlsFollowDirection(val wireName: String) {
    Client("client"), Server("server"), Unknown("unknown")
}

/** No plaintext is available. These reasons do not diagnose certificate pinning. */
enum class TlsFollowUnavailableReason(val wireName: String) {
    NotTls("NOT_TLS"),
    SecretsNotConfigured("SECRETS_NOT_CONFIGURED"),
    HandshakeIncomplete("HANDSHAKE_INCOMPLETE"),
    NoDecryptedApplicationData("NO_DECRYPTED_APPLICATION_DATA"),
    Unknown("UNKNOWN");

    companion object {
        fun fromWire(value: String) = entries.firstOrNull { it.wireName == value } ?: Unknown
    }
}

/** frameNumber identifies the follower's originating/reassembly frame, not a raw byte range. */
class TlsFollowRecord(
    val frameNumber: Long,
    val direction: TlsFollowDirection,
    val fromServer: Boolean?,
    val bytes: ByteArray
) {
    val byteLength: Int get() = bytes.size

    // Prevent incidental logging of plaintext or a Base64 representation.
    override fun toString() = "TlsFollowRecord(frameNumber=$frameNumber, direction=$direction, byteLength=$byteLength)"
}

/** A bounded preview, deliberately separate from the legacy TCP/UDP result. */
data class TlsFollowResult(
    val success: Boolean,
    val scope: TlsFollowScope,
    val dissectionGeneration: Long,
    val directionKnown: Boolean,
    val records: List<TlsFollowRecord>,
    val truncated: Boolean,
    val incomplete: Boolean,
    val streamId: Int?,
    val connectionFrames: Int?,
    val errorCode: TlsErrorCode?,
    val unavailableReason: TlsFollowUnavailableReason?
) {
    val protocol: String get() = "tls"
    val byteLength: Int get() = records.sumOf { it.byteLength }
}

/** Malformed JNI data never becomes successful empty content, nor enters an exception message. */
class TlsFollowException(val errorCode: String) : IllegalStateException("TLS follow: $errorCode")

/**
 * Result of the bounded, chunked full-stream export (TLS-308). Unlike [TlsFollowResult] this carries
 * no bytes and no per-record list: the plaintext went straight to a file. `sha256` is the digest of
 * exactly the bytes written, so a caller can verify the file. A cancelled or failed export never
 * reports success, and the native side removes the partial file. `toString` never includes bytes.
 */
class TlsFollowExportResult(
    val success: Boolean,
    val byteLength: Long,
    val sha256: String?,
    val truncated: Boolean,
    val incomplete: Boolean,
    val directionKnown: Boolean,
    val streamId: Int?,
    val connectionFrames: Int?,
    val errorCode: TlsErrorCode?,
    val unavailableReason: TlsFollowUnavailableReason?
) {
    val protocol: String get() = "tls"
    val scope: TlsFollowScope get() = TlsFollowScope.CompleteConnection

    override fun toString() =
        "TlsFollowExportResult(success=$success, byteLength=$byteLength, truncated=$truncated, " +
            "incomplete=$incomplete, errorCode=$errorCode)"
}
