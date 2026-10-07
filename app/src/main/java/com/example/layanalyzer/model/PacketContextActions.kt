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
    val error: String? = null
)
