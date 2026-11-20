// Copyright (c) 2026 cheig; GPL-3.0.
package com.example.layanalyzer.capture

import com.example.layanalyzer.capture.socks.SocksNioServer
import com.example.layanalyzer.capture.socks.SocksNioTcpServer
import com.example.layanalyzer.capture.socks.SocksRuntimeLimits
import com.example.layanalyzer.capture.tls.SocksNioTlsGateway
import java.io.Closeable
import java.io.IOException
import java.net.DatagramSocket
import java.net.InetAddress
import java.net.Socket
import java.util.UUID
import java.util.concurrent.atomic.AtomicBoolean

/**
 * Authenticated loopback SOCKS entry for HEV. All forwarding belongs to two NIO event loops.
 * Socket preparation must protect/bind the unconnected channel adapter before any network I/O.
 * Runtime capacity, routing policy and network callbacks are frozen for the entire capture.
 */
internal class DirectSocks5Server(
    private val prepareTcp: (Socket) -> Unit,
    private val prepareUdp: (DatagramSocket) -> Unit,
    private val resolveHost: (String) -> Array<InetAddress>,
    private val generateCredentials: () -> SocksCredentials = { SocksCredentials.generate() },
    private val tlsGateway: SocksNioTlsGateway? = null,
    private val udpPolicy: UdpDestinationPolicy = UdpDestinationPolicy.PRESERVE,
    val runtimeLimits: SocksRuntimeLimits = SocksRuntimeLimits()
) : Closeable {
    private val nio = SocksNioTcpServer(
        runtimeLimits.tcpProfile, udpProfile = runtimeLimits.udpProfile,
        production = true, runtimeLimits = runtimeLimits
    )
    private val running = AtomicBoolean(false)
    private val statsId = UUID.randomUUID().toString()
    @Volatile private var activeCredentials: SocksCredentials? = null

    val port: Int
        get() = nio.stats().server.let {
            check(it.state == SocksNioServer.State.RUNNING) { "SOCKS5 server is not running." }
            checkNotNull(it.port)
        }

    val credentials: SocksCredentials
        get() = activeCredentials?.takeIf {
            running.get() && nio.stats().server.state == SocksNioServer.State.RUNNING
        } ?: throw IllegalStateException("SOCKS5 credentials exist only while the server is running.")

    fun stats(): UpstreamStats = nio.stats().let {
        UpstreamStats(it.tcpSentBytes + (it.udp?.traffic?.sentBytes ?: 0),
            it.tcpReceivedBytes + (it.udp?.traffic?.receivedBytes ?: 0))
    }

    /** Final counters remain available after stop, including an incomplete bounded stop. */
    fun nioStats(): SocksNioTcpServer.Stats = nio.stats()

    fun sessionStats(): SocksSessionStats = nio.stats().let {
        val admission = it.server.admission
        SocksSessionStats(admission?.rejectedHandshakes ?: 0, admission?.rejectedTcp ?: 0,
            admission?.rejectedUdp ?: 0, it.expiredUdp, statsId,
            it.server.state == SocksNioServer.State.RUNNING,
            admission?.handshakes ?: SocksBudgetStats(0, 0, runtimeLimits.authentication),
            admission?.tcp ?: SocksBudgetStats(0, 0, runtimeLimits.tcp),
            admission?.udp ?: SocksBudgetStats(0, 0, runtimeLimits.udp), it.failureEvents)
    }

    fun udpInterventionStats(): UdpInterventionStats = nio.stats().udp?.traffic?.let {
        UdpInterventionStats(it.blockedDatagrams, it.blockedBytes)
    } ?: UdpInterventionStats()

    fun start(networkGeneration: Long = 0): Int {
        require(networkGeneration >= 0)
        check(nio.stats().server.state in setOf(SocksNioServer.State.NEW, SocksNioServer.State.STOPPED)) {
            "NIO server must finish its previous stop before restart"
        }
        check(running.compareAndSet(false, true)) { "SOCKS5 server is already running." }
        val sessionCredentials = try { generateCredentials() } catch (error: Throwable) {
            running.set(false)
            throw error
        }
        activeCredentials = sessionCredentials
        return try {
            val boundPort = nio.start(SocksNioTcpServer.StartRequest(sessionCredentials, networkGeneration,
                resolveHost, prepareTcp, route = { request ->
                    when (tlsGateway?.route(request.port)) {
                        null, SocksNioTlsGateway.Route.DIRECT -> SocksNioTcpServer.Route.DIRECT
                        SocksNioTlsGateway.Route.GATEWAY -> SocksNioTcpServer.Route.TLS_GATEWAY
                        SocksNioTlsGateway.Route.UNAVAILABLE -> SocksNioTcpServer.Route.REJECT
                    }
                }, tlsGateway = tlsGateway, prepareUdp = prepareUdp, udpPolicy = udpPolicy))
            check(running.get()) { "NIO SOCKS start was canceled" }
            boundPort
        } catch (error: Throwable) {
            running.set(false)
            if (nio.stop()) {
                sessionCredentials.discard()
                activeCredentials = null
            }
            throw error
        }
    }

    override fun close() {
        running.set(false)
        if (!nio.stop()) throw IOException("NIO SOCKS stop timed out; owner cleanup is incomplete")
        activeCredentials?.discard()
        activeCredentials = null
    }

    data class UpstreamStats(val sentBytes: Long, val receivedBytes: Long)
}
