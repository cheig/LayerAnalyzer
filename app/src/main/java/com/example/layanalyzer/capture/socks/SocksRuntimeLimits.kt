// Copyright (c) 2026 cheig; GPL-3.0.
package com.example.layanalyzer.capture.socks

import org.json.JSONObject

/**
 * Frozen at capture start. The expanded default is a target configuration, not a claim that
 * the full device capacity matrix has passed. Keep the historical acceptance marker honest.
 */
internal data class SocksRuntimeLimits(
    val tcp: Int = DEFAULT_TCP,
    val udp: Int = DEFAULT_UDP,
    val authentication: Int = DEFAULT_AUTHENTICATION,
    val tlsHandshakes: Int = TLS_HANDSHAKES
) {
    init {
        require(tcp in setOf(64, 128, 256, 512, 1024))
        require(udp in setOf(64, 128, 256))
        require(authentication in setOf(64, 128) && tlsHandshakes == TLS_HANDSHAKES)
    }

    /** True only for the historically device-accepted tier, independently of build defaults. */
    val deviceAccepted: Boolean
        get() = tcp == ACCEPTED_TCP && udp == ACCEPTED_UDP && authentication == ACCEPTED_AUTHENTICATION

    val tcpProfile get() = SocksNioTcpProfile.entries.single { it.tcp == tcp }
    val udpProfile get() = SocksNioUdpProfile.entries.single { it.udp == udp }
    val resourcesPerLoop get() = authentication + tcp + udp + 1
    val channelsPerLoop get() = authentication + 2 * tcp + 3 * udp + 1
    val timersPerLoop get() = 2 * authentication + 4 * tcp + 3 * udp
    val tcpBufferBytes get() = tcp * 2 * SocksTcpBufferBudget.MAX_DIRECTION_BYTES

    fun eventLoopConfig(): SocksEventLoopConfig {
        return SocksEventLoopConfig(timerCapacity = timersPerLoop,
            resourceCapacity = resourcesPerLoop, channelCapacity = channelsPerLoop, runtimeLimits = this)
    }

    /** Fixed wire identity for start-config v2 and reports, never a forwarding selector. */
    fun encode() = JSONObject().put("mode", "NIO").put("tcp", tcp).put("udp", udp)
        .put("authentication", authentication).put("tlsHandshakes", tlsHandshakes)

    companion object {
        const val DEFAULT_TCP = 1024
        const val DEFAULT_UDP = 256
        const val DEFAULT_AUTHENTICATION = 128

        // The historical fully measured tier. Do not promote the new defaults merely because
        // a smoke test passes; report VALIDATION_ONLY until the device matrix is reviewed.
        const val ACCEPTED_TCP = 64
        const val ACCEPTED_UDP = 64
        const val ACCEPTED_AUTHENTICATION = 64

        /** Simultaneous TLS handshakes are an independent budget, not part of the tier decision. */
        const val TLS_HANDSHAKES = 8
    }
}
