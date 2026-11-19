// Copyright (c) 2026 cheig
// LayerAnalyzer - https://github.com/cheig/LayerAnalyzer
// Licensed under GNU GPL version 3; see LICENSE.

package com.example.layanalyzer.model

import androidx.compose.runtime.Immutable

@Immutable
data class PacketFollowFilters(
    val sipCall: String? = null,
    val udpStream: String? = null,
    val tcpStream: String? = null
) {
    val isEmpty: Boolean
        get() = sipCall == null && udpStream == null && tcpStream == null
}

@Immutable
data class PacketContextActionsState(
    val frameNumber: Long? = null,
    val isLoading: Boolean = false,
    val followFilters: PacketFollowFilters = PacketFollowFilters(),
    val error: String? = null,
    val tlsFollow: PacketTlsFollowAction = PacketTlsFollowAction()
)

/** Metadata only: the context menu never stores decrypted bytes. P3 localizes these reasons. */
@Immutable
data class PacketTlsFollowAction(
    val enabled: Boolean = false,
    val isLoading: Boolean = false,
    val dissectionGeneration: Long? = null,
    val errorCode: TlsErrorCode? = TlsErrorCode.NOT_READY,
    val unavailableReason: TlsFollowUnavailableReason? = null
) {
    companion object {
        fun fromResult(result: TlsFollowResult) = PacketTlsFollowAction(
            enabled = result.success && result.records.isNotEmpty() && result.byteLength > 0,
            dissectionGeneration = result.dissectionGeneration,
            errorCode = if (result.success) null else result.errorCode,
            unavailableReason = result.unavailableReason
        )
    }
}
