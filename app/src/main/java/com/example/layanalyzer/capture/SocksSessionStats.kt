// Copyright (c) 2026 cheig; GPL-3.0.
package com.example.layanalyzer.capture

import java.net.InetAddress

/** Independent budgets: UDP/DNS cannot consume TCP forwarding capacity. */
internal data class SocksSessionLimits(
    val handshakes: Int = 64,
    val tcp: Int = 64,
    val udp: Int = 64,
    val dnsIdleMillis: Int = 10_000,
    val udpIdleMillis: Int = 60_000
) {
    init {
        require(handshakes in 1..64 && tcp in 1..64 && udp in 1..64)
        require(dnsIdleMillis in 1..60_000 && udpIdleMillis in dnsIdleMillis..60_000)
    }
}

internal data class SocksSessionStats(
    val rejectedHandshakes: Long,
    val rejectedTcp: Long,
    val rejectedUdp: Long,
    val expiredUdp: Long,
    val serverId: String,
    val running: Boolean,
    val handshakes: SocksBudgetStats,
    val tcp: SocksBudgetStats,
    val udp: SocksBudgetStats,
    /** Fixed reason codes, per event, not failed sessions. I/O/EOF may include peer teardown. */
    val failureEvents: Map<String, Long>
)

/**
 * The forwarding-layer UDP screen of one capture (TLS-314, design §10.1).
 *
 * Mirrors [com.example.layanalyzer.capture.tls.SocksNioTlsGateway.route]: the server asks one question per datagram and
 * applies no rule of its own, so the rule that is validated, the rule that is
 * reported and the rule that is applied are literally the same object. The
 * question is a destination address and port — never a UID and never an SNI,
 * because neither exists at this layer — which is why a scope that can only be
 * named per HTTPS domain cannot be promised here.
 *
 * Implementations are called from the owning NIO event loop, once per datagram.
 */
internal fun interface UdpDestinationPolicy {
    fun decide(address: InetAddress, port: Int): UdpVerdict

    companion object {
        /**
         * The default, and the only policy a capture without interception has
         * (C03 1): every datagram is forwarded exactly as it was before this
         * feature existed, IPv4 and IPv6 alike.
         */
        val PRESERVE: UdpDestinationPolicy = UdpDestinationPolicy { _, _ -> UdpVerdict.Forward }
    }
}

/** The two verdicts a datagram can receive. Both apply to every address family. */
internal enum class UdpVerdict {
    /** Forwarded unchanged. */
    Forward,

    /** Dropped by the frozen UDP/443 intervention. */
    BlockSelectedUdp443
}

/** One run's UDP interventions: counts only, never a destination or a payload. */
internal data class UdpInterventionStats(
    val blockedDatagrams: Long = 0,
    val blockedBytes: Long = 0
)
