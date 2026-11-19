// Copyright (c) 2026 cheig; GPL-3.0.
package com.example.layanalyzer.capture.socks

import com.example.layanalyzer.capture.SocksCredentials
import com.example.layanalyzer.capture.SocksRequest
import com.example.layanalyzer.capture.UdpDestinationPolicy
import com.example.layanalyzer.capture.tls.SocksNioTlsGateway
import java.io.IOException
import java.net.DatagramSocket
import java.net.InetAddress
import java.net.Socket
import java.nio.channels.Selector
import java.nio.channels.ServerSocketChannel
import java.util.concurrent.CopyOnWriteArrayList
import java.util.concurrent.ConcurrentHashMap
import java.util.concurrent.atomic.AtomicLong
import java.util.concurrent.atomic.AtomicReference

/**
 * Shared NIO assembly for the production facade and finite controlled validation profiles.
 * No session/relay worker: listener, auth, connect and both relay directions share two owners.
 * An explicit route decision is mandatory; TLS candidates NEVER fall back to direct. Legacy
 * component tests keep TCP_64; frozen runtime profiles permit larger Go-linked capacities.
 * Each start freezes a request and uses the listener's actual generation for a fresh DNS scope
 * and buffer budget. Lookup/prepare/route closures must themselves capture immutable network
 * and policy values; only lookup may block. The process DNS executor survives every stop.
 */
internal class SocksNioTcpServer(
    val profile: SocksNioTcpProfile,
    private val resolver: SocksResolver = SocksResolver.shared,
    listenerFactory: () -> ServerSocketChannel = { ServerSocketChannel.open() },
    selectorFactory: (Int) -> Selector = { Selector.open() },
    threadFactory: (Runnable, String) -> Thread = { task, name -> Thread(task, name) },
    private val connectIo: SocksNioTcpConnect.ConnectIo = SocksNioTcpConnect.ConnectIo.CHANNEL,
    private val gatewayIo: SocksNioGatewayConnect.GatewayIo = SocksNioGatewayConnect.GatewayIo.CHANNEL,
    private val clientIo: SocksNioHandshake.ClientIo = SocksNioHandshake.ClientIo.CHANNEL,
    private val sessionNanoClock: () -> Long = System::nanoTime,
    private val gatewayEstablishmentTimeoutNanos: Long = SocksNioGatewayConnect.ESTABLISHMENT_TIMEOUT_NANOS,
    private val gatewayDnsTimeoutNanos: Long = SocksNioTcpResolve.DNS_TIMEOUT_NANOS,
    val udpProfile: SocksNioUdpProfile? = null,
    private val udpIo: UdpDataPlane.ChannelIo = UdpDataPlane.ChannelIo.CHANNEL,
    /** Distinguishes the facade entry from legacy component test assemblies. */
    private val production: Boolean = false,
    val runtimeLimits: SocksRuntimeLimits? = null
) : AutoCloseable {
    init {
        require(runtimeLimits != null || udpProfile == null || profile == SocksNioTcpProfile.TCP_64) {
            "P4 mixed validation requires TCP_64"
        }
        require(runtimeLimits == null || (runtimeLimits.tcpProfile == profile && runtimeLimits.udpProfile == udpProfile))
        require(!production || runtimeLimits != null)
    }
    enum class Route { DIRECT, TLS_GATEWAY, REJECT }
    data class StartRequest(
        val credentials: SocksCredentials,
        val networkGeneration: Long,
        val lookup: (String) -> Array<InetAddress>,
        val prepareTcp: (Socket) -> Unit,
        val route: (SocksRequest) -> Route,
        /** Owned by this run after start; stop closes it. Every restart needs a fresh gateway. */
        val tlsGateway: SocksNioTlsGateway? = null,
        /** Required for UDP profiles; frozen protect/bind callback, never a blocking operation. */
        val prepareUdp: ((DatagramSocket) -> Unit)? = null,
        val udpPolicy: UdpDestinationPolicy = UdpDestinationPolicy.PRESERVE
    ) {
        init { require(networkGeneration >= 0) }
    }
    data class Stats(
        val mode: String,
        val profile: SocksNioTcpProfile,
        val snapshotVersion: Int,
        val supportsUdp: Boolean,
        val supportsTlsGateway: Boolean,
        val eventLoopConfig: SocksEventLoopConfig,
        val eventLoopThreadsAlive: Int,
        val eventLoopThreadLimit: Int,
        val bufferCapacityBytes: Int,
        val buffers: SocksTcpBufferBudget.Snapshot?,
        val server: SocksNioServer.Stats,
        val runResolver: SocksResolver.ScopeStats?,
        /** Includes work still running for previous captures/other servers; not a run counter. */
        val processResolver: SocksResolver.Stats,
        val processResolverLimits: SocksResolver.Limits,
        val connectedRelays: Long,
        val rejectedRoutes: Long,
        val rejectedUdp: Long,
        /** READY verdicts/setup failures are distinct from replies fully drained into relay. */
        val gateway: SocksNioGatewayConnect.Stats?,
        val gatewayRelays: Long,
        val udpProfile: SocksNioUdpProfile?,
        val udp: UdpDataPlaneRuntime.Snapshot?,
        val tcpSentBytes: Long,
        val tcpReceivedBytes: Long,
        val expiredUdp: Long,
        val failureEvents: Map<String, Long>,
        val effectiveRuntime: SocksRuntimeLimits?
    )

    private val startingRequest = AtomicReference<StartRequest?>()
    private val runGate = Any()
    @Volatile private var current: Run? = null
    private val config = runtimeLimits?.eventLoopConfig() ?: udpProfile?.eventLoopConfig() ?: profile.eventLoopConfig()

    private inner class Run(val generation: Long, request: StartRequest) {
        val networkGeneration = request.networkGeneration
        val budget = SocksTcpBufferBudget(profile.bufferBytes)
        val scope = resolver.newScope(generation, request.networkGeneration, request.lookup)
        val udp = udpProfile?.let { UdpDataPlaneRuntime() }
        val threads = CopyOnWriteArrayList<Thread>() // exactly two, new list per run
        val connected = AtomicLong()
        val rejectedRoutes = AtomicLong()
        val rejectedUdp = AtomicLong()
        val gatewayRelays = AtomicLong()
        val tcpSent = AtomicLong()
        val tcpReceived = AtomicLong()
        val expiredUdp = AtomicLong()
        val failures = ConcurrentHashMap<String, AtomicLong>()
        val supportsTlsGateway = request.tlsGateway != null
        private var credentials: SocksCredentials? = request.credentials
        private var gateway: SocksNioTlsGateway? = request.tlsGateway
        @Volatile private var gatewayConnector: SocksNioGatewayConnect? = null
        @Volatile private var stoppedGatewayStats: SocksNioGatewayConnect.Stats? = null
        @Volatile var handshake: SocksNioHandshake? = null
            private set

        init {
            val relay = TcpRelay(budget, onForwarded = { upload, bytes ->
                (if (upload) tcpSent else tcpReceived).addAndGet(bytes.toLong())
            })
            val connector = SocksNioTcpConnect(request.prepareTcp, {
                if (relay.start(it) != null) connected.incrementAndGet()
            }, io = connectIo)
            val resolve = SocksNioTcpResolve(scope, connector)
            val gatewayReply = SocksNioGatewayReply(onConnected = {
                if (relay.start(it) != null) { connected.incrementAndGet(); gatewayRelays.incrementAndGet() }
            })
            val tlsConnector = request.tlsGateway?.let {
                SocksNioGatewayConnect(it, gatewayReply::ready, io = gatewayIo)
            }.also { gatewayConnector = it }
            val gatewayResolve = tlsConnector?.let {
                SocksNioGatewayResolve(scope, it, gatewayEstablishmentTimeoutNanos, gatewayDnsTimeoutNanos)
            }
            val association = udp?.let { runtime ->
                UdpAssociation(checkNotNull(request.prepareUdp), { active ->
                    val driver = UdpDataPlane(active, runtime, scope, request.udpPolicy, udpIo)
                    UdpIdleTimeout.attach(active, driver)
                })
            }
            handshake = SocksNioHandshake({ request.credentials }, {
                admitted(it, request, relay, connector, resolve, tlsConnector, gatewayResolve, association)
            }, clientIo, onAuthenticationRejected = {
                failures.computeIfAbsent("authentication_rejected") { AtomicLong() }.incrementAndGet()
            })
        }

        private fun admitted(entry: SocksNioHandshake.AdmittedRequest, request: StartRequest,
            relay: TcpRelay, connector: SocksNioTcpConnect, resolve: SocksNioTcpResolve,
            tlsConnector: SocksNioGatewayConnect?, gatewayResolve: SocksNioGatewayResolve?, association: UdpAssociation?) {
            check(entry.session.captureGeneration == generation)
            if (entry.request.command != SocksProtocol.COMMAND_CONNECT) {
                if (association != null) {
                    association.start(entry)
                    return
                }
                rejectedUdp.incrementAndGet()
                connector.fail(entry, IOException("NIO TCP validation does not support UDP"),
                    SocksProtocol.REPLY_COMMAND_NOT_SUPPORTED)
                return
            }
            val selected = try {
                val route = request.route(entry.request)
                val gatewayRoute = request.tlsGateway?.route(entry.request.port)
                when {
                    route == Route.REJECT -> Route.REJECT
                    route == Route.DIRECT && (gatewayRoute == null || gatewayRoute == SocksNioTlsGateway.Route.DIRECT) -> Route.DIRECT
                    route == Route.TLS_GATEWAY && gatewayRoute == SocksNioTlsGateway.Route.GATEWAY -> Route.TLS_GATEWAY
                    else -> Route.REJECT
                }
            } catch (_: Exception) { Route.REJECT }
            if (selected == Route.REJECT) {
                rejectedRoutes.incrementAndGet()
                val error = IOException("NIO TCP route unavailable or inconsistent with gateway policy")
                if (tlsConnector == null) connector.fail(entry, error)
                else tlsConnector.fail(entry, error, SocksNioGatewayConnect.Stage.DESCRIPTION)
                return
            }
            // Reserve before ANY DNS or socket creation. A successful connect always has room
            // for both bounded directions, even while other sessions are backpressured.
            if (!relay.reserve(entry.session)) {
                connector.fail(entry, TcpRelay.BufferBudgetExceededException())
                return
            }
            if (selected == Route.TLS_GATEWAY) checkNotNull(gatewayResolve).connect(entry)
            else resolve.connect(entry)
        }

        fun gatewayStats() = gatewayConnector?.stats() ?: stoppedGatewayStats

        fun sessionClosed(cause: Throwable?) {
            if (cause is UdpIdleTimeout.IdleExpiredException) expiredUdp.incrementAndGet()
            if (cause != null) {
                val reason = when (cause) {
                    is UdpIdleTimeout.IdleExpiredException -> "udp_idle"
                    is SocksNioGatewayConnect.Failure -> "gateway_${cause.stage.name.lowercase()}_${cause.reason.name.lowercase()}"
                    is SocksSession.DeadlineExceededException -> "session_timeout"
                    is TcpRelay.BufferBudgetExceededException -> "tcp_buffer_capacity"
                    else -> "session_io"
                }
                failures.computeIfAbsent(reason) { AtomicLong() }.incrementAndGet()
            }
        }

        fun stop() {
            // Mark only: the server next stops both owners; their cleanup releases UDP scratch.
            udp?.close()
            scope.close()
            runCatching { gateway?.close() }
            gateway = null
        }

        /** Only after both owners have actually exited; a timed-out stop retains their inputs. */
        @Synchronized fun finishStop() {
            stoppedGatewayStats = gatewayConnector?.stats() ?: stoppedGatewayStats
            gatewayConnector = null
            credentials?.discard()
            credentials = null
            // Keep only counters/closed scope for the stopped snapshot. Network closures in the
            // handshake/connector graph are released after the owners finish their cleanup.
            handshake = null
        }
    }

    private val server = SocksNioServer(object : SocksNioServer.SessionHandler {
        override fun onSession(session: SocksSession, registration: SocksEventLoop.Registration) {
            val run = checkNotNull(current)
            check(run.generation == session.captureGeneration)
            val handshake = run.handshake
            if (handshake == null) session.close() else handshake.onSession(session, registration)
        }
        override fun onReady(session: SocksSession, registration: SocksEventLoop.Registration, ops: Int) {
            error("Handshake must install its owner handler")
        }
    }, config = config, listenerFactory = listenerFactory, selectorFactory = selectorFactory,
        sessionNanoClock = sessionNanoClock,
        threadFactory = { task, name -> threadFactory(task, name).also { checkNotNull(current).threads.add(it) } },
        onRunStarting = { generation -> synchronized(runGate) {
            current?.finishStop() // server has verified that the previous group is fully stopped
            current = Run(generation, checkNotNull(startingRequest.get()))
        } },
        onRunStopping = { generation -> current?.takeIf { it.generation == generation }?.stop() },
        onSessionClosed = { cause -> current?.sessionClosed(cause) })

    /** Credentials/gateway belong to an accepted start and are closed on stop or startup failure. */
    fun start(request: StartRequest, port: Int = 0): Int {
        require(udpProfile == null || request.prepareUdp != null) {
            "UDP validation requires an explicit prepareUdp callback"
        }
        require(runtimeLimits != null || request.tlsGateway == null || profile == SocksNioTcpProfile.TCP_64) {
            "P3 TLS gateway validation requires TCP_64; Go capacity has not been expanded"
        }
        check(startingRequest.compareAndSet(null, request)) { "Concurrent start" }
        try { return server.start(port) } finally {
            startingRequest.set(null)
            finishStoppedRun()
        }
    }

    fun stop(timeoutMillis: Long = config.shutdownTimeoutMillis): Boolean = server.stop(timeoutMillis).also {
        if (it) finishStoppedRun()
    }

    private fun finishStoppedRun() {
        val state = server.stats() // server.start holds its gate before onRunStarting takes runGate
        synchronized(runGate) {
            current?.takeIf { state.state == SocksNioServer.State.STOPPED && it.generation == state.captureGeneration }
                ?.finishStop()
        }
    }

    /** Stale notifications cannot stop a newer frozen network. No workers are joined here. */
    fun invalidateNetwork(networkGeneration: Long): Boolean {
        val run = current ?: return false
        if (run.networkGeneration != networkGeneration) return false
        return server.stop(expectedGeneration = run.generation).also { if (it) finishStoppedRun() }
    }

    fun stats(): Stats {
        finishStoppedRun()
        val run = current
        return Stats(if (production) "NIO" else if (udpProfile == null) "NIO_TCP_VALIDATION" else "NIO_UDP_VALIDATION",
            profile, if (udpProfile == null) 2 else 3, udpProfile != null, run?.supportsTlsGateway == true, config,
            run?.threads?.count { it.isAlive } ?: 0, SocksEventLoopGroup.LOOP_COUNT,
            profile.bufferBytes, run?.budget?.snapshot(), server.stats(), run?.scope?.stats(),
            resolver.stats(), resolver.configuration, run?.connected?.get() ?: 0,
            run?.rejectedRoutes?.get() ?: 0, run?.rejectedUdp?.get() ?: 0,
            run?.gatewayStats(), run?.gatewayRelays?.get() ?: 0, udpProfile, run?.udp?.snapshot(),
            run?.tcpSent?.get() ?: 0, run?.tcpReceived?.get() ?: 0, run?.expiredUdp?.get() ?: 0,
            run?.failures?.mapValues { it.value.get() } ?: emptyMap(), runtimeLimits)
    }

    override fun close() { stop() }
}
