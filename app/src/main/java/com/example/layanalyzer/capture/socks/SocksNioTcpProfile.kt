// Copyright (c) 2026 cheig; GPL-3.0.
package com.example.layanalyzer.capture.socks

/** Finite controlled TCP profiles. Only a frozen runtime configuration connects production. */
internal enum class SocksNioTcpProfile(val id: String, val tcp: Int) {
    TCP_64("nio-tcp-validation-64-v1", 64),
    TCP_128("nio-tcp-validation-128-v1", 128),
    TCP_256("nio-tcp-validation-256-v1", 256),
    TCP_512("nio-tcp-validation-512-v1", 512),
    TCP_1024("nio-tcp-validation-1024-v1", 1024);

    val handshakes: Int get() = 64
    // NIO-105 transfers a recognized UDP request's lease before this TCP-only assembly rejects
    // it. Those short failure-writer scopes also need room; no UDP socket is ever constructed.
    val rejectingUdp: Int get() = 64
    val bufferBytes: Int get() = tcp * 2 * SocksTcpBufferBudget.MAX_DIRECTION_BYTES
    // Global worst case per loop, including listener and provisional auth resources. Ownership
    // can become uneven as old sessions close; these bounds never rely on perfect balancing.
    val resourcesPerLoop: Int get() = handshakes + rejectingUdp + tcp + 1
    val channelsPerLoop: Int get() = handshakes + rejectingUdp + 2 * tcp + 1
    val timersPerLoop: Int get() = 2 * (handshakes + rejectingUdp) + 4 * tcp

    fun eventLoopConfig() = SocksEventLoopConfig(
        timerCapacity = timersPerLoop,
        resourceCapacity = resourcesPerLoop,
        channelCapacity = channelsPerLoop,
        tcpValidationProfile = this
    )
}
