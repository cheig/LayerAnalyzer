// Copyright (c) 2026 cheig
// LayerAnalyzer - https://github.com/cheig/LayerAnalyzer
// Licensed under GNU GPL version 3; see LICENSE.

package com.example.layanalyzer.capture.socks

/** Internal infrastructure; larger limits require an explicit, finite validation profile. */
internal data class SocksEventLoopConfig(
    val commandCapacity: Int = 128,
    val completionCapacity: Int = 128,
    val timerCapacity: Int = 256,
    // 64 auth + 64 TCP + 64 UDP scopes, and 64 + 2*64 + 3*64 + listener channels.
    val resourceCapacity: Int = 192,
    val channelCapacity: Int = 385,
    val commandsPerTurn: Int = 32,
    val completionsPerTurn: Int = 32,
    val timersPerTurn: Int = 32,
    val readinessPerTurn: Int = 64,
    val idleSelectMillis: Long = 1_000,
    val shutdownTimeoutMillis: Long = 2_000,
    val tcpValidationProfile: SocksNioTcpProfile? = null,
    val udpValidationProfile: SocksNioUdpProfile? = null,
    val runtimeLimits: SocksRuntimeLimits? = null
) {
    init {
        require(commandCapacity in 1..128 && completionCapacity in 1..128)
        require(tcpValidationProfile == null || udpValidationProfile == null)
        require(runtimeLimits == null || (tcpValidationProfile == null && udpValidationProfile == null))
        require(timerCapacity in 1..(runtimeLimits?.timersPerLoop ?: udpValidationProfile?.timersPerLoop ?: tcpValidationProfile?.timersPerLoop ?: 256))
        require(resourceCapacity in 1..(runtimeLimits?.resourcesPerLoop ?: udpValidationProfile?.resourcesPerLoop ?: tcpValidationProfile?.resourcesPerLoop ?: 192))
        require(channelCapacity in 1..(runtimeLimits?.channelsPerLoop ?: udpValidationProfile?.channelsPerLoop ?: tcpValidationProfile?.channelsPerLoop ?: 385))
        require(commandsPerTurn in 1..commandCapacity && completionsPerTurn in 1..completionCapacity)
        require(timersPerTurn in 1..timerCapacity && readinessPerTurn in 1..channelCapacity)
        require(idleSelectMillis in 1..1_000 && shutdownTimeoutMillis in 0..60_000)
    }
}
