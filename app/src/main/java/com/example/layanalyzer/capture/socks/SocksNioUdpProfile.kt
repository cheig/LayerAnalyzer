// Copyright (c) 2026 cheig; GPL-3.0.
package com.example.layanalyzer.capture.socks

/** P4 internal mixed-service validation only. TCP/TLS stays at 64; production is unchanged. */
internal enum class SocksNioUdpProfile(val id: String, val udp: Int) {
    UDP_64("nio-udp-validation-64-v1", 64),
    UDP_128("nio-udp-validation-128-v1", 128),
    UDP_256("nio-udp-validation-256-v1", 256);

    val tcp: Int get() = 64
    val handshakes: Int get() = 64
    // Any owner must fit the whole admitted population, including provisional auth and listener.
    // UDP: three channels, one resource, at most idle + DNS deadline + retry timers.
    val resourcesPerLoop: Int get() = handshakes + tcp + udp + 1
    val channelsPerLoop: Int get() = handshakes + 2 * tcp + 3 * udp + 1
    val timersPerLoop: Int get() = 2 * handshakes + 4 * tcp + 3 * udp

    fun eventLoopConfig() = SocksEventLoopConfig(
        timerCapacity = timersPerLoop,
        resourceCapacity = resourcesPerLoop,
        channelCapacity = channelsPerLoop,
        udpValidationProfile = this
    )
}
