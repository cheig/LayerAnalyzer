// Copyright (c) 2026 cheig; GPL-3.0.
package com.example.layanalyzer.capture

import com.example.layanalyzer.capture.socks.SocksNioServer
import com.example.layanalyzer.capture.socks.SocksNioTcpProfile
import com.example.layanalyzer.capture.socks.SocksNioTcpServer
import com.example.layanalyzer.capture.socks.SocksNioUdpProfile
import com.example.layanalyzer.capture.socks.SocksProtocol
import com.example.layanalyzer.capture.socks.SocksRuntimeLimits
import java.io.File
import java.io.IOException
import java.net.DatagramPacket
import java.net.DatagramSocket
import java.net.InetAddress
import java.net.InetSocketAddress
import java.net.Socket
import java.net.SocketTimeoutException
import java.nio.ByteBuffer
import java.nio.channels.SelectionKey
import java.nio.channels.Selector
import java.nio.channels.ServerSocketChannel
import java.nio.channels.SocketChannel
import java.util.Locale
import java.util.concurrent.ConcurrentLinkedQueue
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicBoolean
import java.util.concurrent.atomic.AtomicInteger
import java.util.concurrent.atomic.AtomicLong
import java.util.concurrent.atomic.AtomicReference
import kotlin.concurrent.thread
import org.junit.AfterClass
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.BeforeClass
import org.junit.Test

/**
 * NIO-505 JVM capacity matrix on a real Windows JVM Selector plus loopback SocketChannel /
 * DatagramChannel. Every tier really establishes its full population and keeps all of it doing
 * sustained bidirectional transfer for one measured window, then records alive count, bytes,
 * throughput, P50/P95 RTT, event-loop threads, process Java threads, stop latency and post-stop
 * zeroing. Also proves an idle event loop does not spin. The deleted BLOCKING implementation
 * is represented only by the recorded NIO-505 baseline and its source revision.
 *
 * NOT a device test. The JVM loopback numbers say nothing about Android FD/PSS/PSS limits, API 26
 * or 5/30-minute device soak; see candidate device validation remains NOT_RUN for the NOT_RUN list.
 */
class SocksNioCapacityMatrixTest {
    private val loopback = InetAddress.getByAddress(byteArrayOf(127, 0, 0, 1))
    private val auth = byteArrayOf(5, 1, 2, 1, 1, 117, 1, 112)
    private val tierSeconds = System.getProperty("nio505.tierSeconds")?.toLongOrNull() ?: 30L

    @Test fun capacityTcp64() { runTcpTier(SocksNioTcpProfile.TCP_64) }
    @Test fun capacityTcp128() { runTcpTier(SocksNioTcpProfile.TCP_128) }
    @Test fun capacityTcp256() { runTcpTier(SocksNioTcpProfile.TCP_256) }
    @Test fun capacityTcp512() { runTcpTier(SocksNioTcpProfile.TCP_512) }
    @Test fun capacityTcp1024() { runTcpTier(SocksNioTcpProfile.TCP_1024, mayHitResourceLimit = true) }

    @Test fun capacityUdp64() { runUdpTier(SocksNioUdpProfile.UDP_64) }
    @Test fun capacityUdp128() { runUdpTier(SocksNioUdpProfile.UDP_128) }
    @Test fun capacityUdp256() { runUdpTier(SocksNioUdpProfile.UDP_256) }


    /**
     * Counts are the evidence, not CPU percentage: a busy-spinning loop would produce millions of
     * turns/selectCalls in four seconds, a correctly throttled idle loop produces one select per
     * idleSelectMillis (1000ms) per loop.
     */
    @Test fun idleEventLoopDoesNotSpin() {
        val server = newServer()
        try {
            server.start(0)
            await("idle loops started") { server.nioStats().eventLoopThreadsAlive == 2 }
            val before = server.nioStats().server.loops
                .map { Triple(it.turns, it.selectCalls, it.emptySelectBackoffs) }
            Thread.sleep(IDLE_WINDOW_MILLIS)
            val loops = server.nioStats().server.loops
            loops.forEachIndexed { index, loop ->
                val (turns0, select0, backoff0) = before[index]
                val turnsDelta = loop.turns - turns0
                val selectDelta = loop.selectCalls - select0
                val backoffDelta = loop.emptySelectBackoffs - backoff0
                writeCsv(TierResult("IDLE", "loop$index", "OK", 0, 0, 0, 0.0, 0.0, 0, 0,
                    Thread.getAllStackTraces().size, 2, -1,
                    "idle ${IDLE_WINDOW_MILLIS}ms turns=$turnsDelta select=$selectDelta backoffs=$backoffDelta"))
                assertTrue("idle loop spun: turns=$turnsDelta select=$selectDelta",
                    turnsDelta < IDLE_TURN_LIMIT && selectDelta < IDLE_TURN_LIMIT)
            }
        } finally {
            runCatching { server.close() }
        }
    }

    // ---- TCP tiers ----

    private fun runTcpTier(profile: SocksNioTcpProfile, mayHitResourceLimit: Boolean = false): TierResult {
        val tier = profile.tcp
        val clients = ArrayList<Socket>()
        var target: TcpEchoServer? = null
        var server: DirectSocks5Server? = null
        val result = try {
            val echo = TcpEchoServer().also { target = it }
            val live = newServer(tcp = tier).also { server = it }
            val port = live.start(0)
            // A successful SOCKS reply proves the request was admitted and both directions
            // reserved, so the population is established connection by connection without a
            // per-connection poll.
            repeat(tier) { clients.add(clientConnect(port, echo.port)) }
            await("tcp admission $tier") { live.sessionStats().tcp.current == tier }
            val load = driveTcp(clients, tierSeconds, TIER_PAYLOAD)
            val snapshot = live.nioStats()
            assertEquals("event loop threads at $tier", 2, snapshot.eventLoopThreadsAlive)
            assertEquals("admitted tcp at $tier", tier, snapshot.server.admission!!.tcp.current)
            val buffers = checkNotNull(snapshot.buffers)
            val started = System.nanoTime()
            live.close()
            val stopMs = TimeUnit.NANOSECONDS.toMillis(System.nanoTime() - started)
            awaitCleanStats(live, "tcp $tier")
            val seconds = load.elapsedNanos / 1_000_000_000.0
            val (p50, p95) = percentiles(load.latencies)
            TierResult("TCP", tier.toString(), "OK", tier,
                snapshot.tcpSentBytes, snapshot.tcpReceivedBytes,
                snapshot.tcpSentBytes / seconds, snapshot.tcpReceivedBytes / seconds, p50, p95,
                load.loadThreads, snapshot.eventLoopThreadsAlive, stopMs,
                "clientBytes=${load.bytes} rtts=${load.roundTrips} reserved=${buffers.reservedBytes} " +
                    "peakAlloc=${buffers.peakAllocatedBytes} accepted=${snapshot.server.acceptedClients} " +
                    "rejected=${snapshot.server.rejectedAdmissions} " +
                    "drops=${snapshot.server.admission!!.rejectedTcp}")
        } catch (error: Throwable) {
            if (mayHitResourceLimit && isResourceExhaustion(error)) {
                TierResult("TCP", tier.toString(), "NOT_RAN", clients.size, 0, 0, 0.0, 0.0, 0, 0,
                    Thread.getAllStackTraces().size, -1, -1, "resource limit: ${rootMessage(error)}")
            } else {
                throw error
            }
        } finally {
            clients.forEach { runCatching { it.close() } }
            runCatching { target?.close() }
            runCatching { server?.close() }
        }
        writeCsv(result)
        return result
    }

    // ---- UDP tiers ----

    private fun runUdpTier(profile: SocksNioUdpProfile): TierResult {
        val tier = profile.udp
        val links = ArrayList<UdpLink>()
        var target: UdpEchoServer? = null
        var server: DirectSocks5Server? = null
        val result = try {
            val echo = UdpEchoServer().also { target = it }
            val live = newServer(tcp = 64, udp = tier).also { server = it }
            val port = live.start(0)
            repeat(tier) { links.add(udpLink(port)) }
            await("udp admission $tier") { live.sessionStats().udp.current == tier }
            val load = driveUdp(links, echo.port, tierSeconds)
            val snapshot = live.nioStats()
            val udp = checkNotNull(snapshot.udp)
            assertEquals("event loop threads at $tier", 2, snapshot.eventLoopThreadsAlive)
            assertEquals("admitted udp at $tier", tier, snapshot.server.admission!!.udp.current)
            assertEquals("udp associations at $tier", tier, udp.associations)
            val started = System.nanoTime()
            live.close()
            val stopMs = TimeUnit.NANOSECONDS.toMillis(System.nanoTime() - started)
            awaitCleanStats(live, "udp $tier")
            val seconds = load.elapsedNanos / 1_000_000_000.0
            val (p50, p95) = percentiles(load.latencies)
            TierResult("UDP", tier.toString(), "OK", tier,
                udp.traffic.sentBytes, udp.traffic.receivedBytes,
                udp.traffic.sentBytes / seconds, udp.traffic.receivedBytes / seconds, p50, p95,
                load.loadThreads, snapshot.eventLoopThreadsAlive, stopMs,
                "clientBytes=${load.bytes} rtts=${load.roundTrips} lost=${load.lost} " +
                    "peakQueued=${udp.peakQueuedPackets} dropped=${udp.queueDroppedPackets} " +
                    "scratch=${udp.scratchBytes} accepted=${snapshot.server.acceptedClients}")
        } finally {
            links.forEach { runCatching { it.close() } }
            runCatching { target?.close() }
            runCatching { server?.close() }
        }
        writeCsv(result)
        return result
    }

    // ---- transfer drivers ----

    /**
     * One measured window of bidirectional request/response load. Every connection is driven in
     * parallel by a fixed number of rotating drivers that visit each connection once per pass.
     * The rotation is what makes a tier
     * number real: a slice-owning driver that runs to the deadline on its first connection would
     * leave the remaining connections idle and measure 4..16 sessions instead of the tier.
     */
    private fun driveTcp(clients: List<Socket>, seconds: Long, payloadSize: Int): Load {
        val latencies = ConcurrentLinkedQueue<Long>()
        val sampled = AtomicInteger()
        val bytes = AtomicLong()
        val roundTrips = AtomicLong()
        val failed = AtomicReference<Throwable>()
        val deadline = System.nanoTime() + TimeUnit.SECONDS.toNanos(seconds)
        val payload = ByteArray(payloadSize) { (it % 251).toByte() }
        val trip: (Socket) -> Unit = { client ->
            val started = System.nanoTime()
            val output = client.getOutputStream()
            output.write(payload)
            output.flush()
            val echoed = readFully(client, payload.size, "tcp echo")
            if (!echoed.contentEquals(payload)) throw IOException("echoed payload does not match")
            val elapsed = System.nanoTime() - started
            if (sampled.incrementAndGet() <= MAX_SAMPLES) latencies.add(elapsed)
            roundTrips.incrementAndGet()
            bytes.addAndGet((payload.size * 2).toLong())
        }
        val drivers = minOf(DRIVER_THREADS, clients.size)
        val workers = (0 until drivers).map { index ->
            thread(name = "nio505-tcp-$index", isDaemon = true) {
                try {
                    val slice = clients.subList(index * clients.size / drivers,
                        (index + 1) * clients.size / drivers)
                    while (System.nanoTime() < deadline && failed.get() == null) {
                        for (client in slice) {
                            if (System.nanoTime() >= deadline || failed.get() != null) break
                            trip(client)
                        }
                    }
                } catch (error: Throwable) {
                    failed.compareAndSet(null, error)
                }
            }
        }
        val startedAt = System.nanoTime()
        // Sample both live load and post-driver thread counts.
        Thread.sleep(minOf(300L, seconds * 1000 / 4))
        val loadThreads = Thread.getAllStackTraces().size
        workers.forEach { it.join(TimeUnit.SECONDS.toMillis(seconds + LOAD_JOIN_GRACE_SECONDS)) }
        if (workers.any { it.isAlive }) throw IOException("TCP driver thread did not finish")
        failed.get()?.let { throw it }
        return Load(bytes.get(), latencies, System.nanoTime() - startedAt, roundTrips.get(), 0L, loadThreads,
            Thread.getAllStackTraces().size)
    }

    /** Same rotation as TCP. Loopback UDP may genuinely drop a datagram, so a miss is counted, not fatal. */
    private fun driveUdp(links: List<UdpLink>, targetPort: Int, seconds: Long): Load {
        val latencies = ConcurrentLinkedQueue<Long>()
        val sampled = AtomicInteger()
        val bytes = AtomicLong()
        val roundTrips = AtomicLong()
        val lost = AtomicLong()
        val failed = AtomicReference<Throwable>()
        val deadline = System.nanoTime() + TimeUnit.SECONDS.toNanos(seconds)
        val payload = ByteArray(UDP_PAYLOAD) { (it % 251).toByte() }
        val drivers = minOf(DRIVER_THREADS, links.size)
        val workers = (0 until drivers).map { index ->
            thread(name = "nio505-udp-$index", isDaemon = true) {
                var consecutiveMisses = 0
                try {
                    val slice = links.subList(index * links.size / drivers, (index + 1) * links.size / drivers)
                    while (System.nanoTime() < deadline && failed.get() == null) {
                        for (link in slice) {
                            if (System.nanoTime() >= deadline || failed.get() != null) break
                            val started = System.nanoTime()
                            if (link.roundTrip(targetPort, payload)) {
                                consecutiveMisses = 0
                                val elapsed = System.nanoTime() - started
                                if (sampled.incrementAndGet() <= MAX_SAMPLES) latencies.add(elapsed)
                                roundTrips.incrementAndGet()
                                bytes.addAndGet((payload.size * 2).toLong())
                            } else {
                                lost.incrementAndGet()
                                if (++consecutiveMisses >= MAX_CONSECUTIVE_MISSES) {
                                    throw IOException("UDP association stopped echoing")
                                }
                            }
                        }
                    }
                } catch (error: Throwable) {
                    failed.compareAndSet(null, error)
                }
            }
        }
        val startedAt = System.nanoTime()
        Thread.sleep(minOf(300L, seconds * 1000 / 4))
        val loadThreads = Thread.getAllStackTraces().size
        workers.forEach { it.join(TimeUnit.SECONDS.toMillis(seconds + LOAD_JOIN_GRACE_SECONDS)) }
        if (workers.any { it.isAlive }) throw IOException("UDP driver thread did not finish")
        failed.get()?.let { throw it }
        return Load(bytes.get(), latencies, System.nanoTime() - startedAt, roundTrips.get(), lost.get(), loadThreads,
            Thread.getAllStackTraces().size)
    }

    // ---- clients ----

    private fun newServer(tcp: Int = 64, udp: Int = 64,
        authentication: Int = AUTH_LIMIT): DirectSocks5Server = DirectSocks5Server(
        prepareTcp = { it.tcpNoDelay = true }, prepareUdp = {}, resolveHost = { arrayOf(loopback) },
        generateCredentials = { SocksCredentials.of("u", "p") }, tlsGateway = null,
        udpPolicy = UdpDestinationPolicy.PRESERVE,
        runtimeLimits = SocksRuntimeLimits(tcp = tcp, udp = udp, authentication = authentication))

    private fun clientConnect(port: Int, targetPort: Int): Socket {
        val client = Socket()
        client.soTimeout = SOCKET_TIMEOUT_MILLIS
        client.tcpNoDelay = true
        client.connect(InetSocketAddress(loopback, port), SOCKET_TIMEOUT_MILLIS)
        val output = client.getOutputStream()
        output.write(auth)
        output.write(SocksProtocol.encodeRequest(
            SocksRequest(SocksProtocol.COMMAND_CONNECT, SocksDestination.Ip(loopback), targetPort)))
        output.flush()
        val greeting = readFully(client, 4, "method/auth reply")
        if (greeting[0].toInt() != 5 || greeting[1].toInt() != 2 || greeting[3].toInt() != 0) {
            throw IOException("authentication failed: ${greeting.contentToString()}")
        }
        val reply = reply(client)
        if (reply[1].toInt() != 0) throw IOException("CONNECT rejected: code=${reply[1].toInt()}")
        return client
    }

    private fun udpLink(port: Int): UdpLink {
        val control = Socket()
        control.soTimeout = SOCKET_TIMEOUT_MILLIS
        control.connect(InetSocketAddress(loopback, port), SOCKET_TIMEOUT_MILLIS)
        val output = control.getOutputStream()
        output.write(auth)
        output.write(SocksProtocol.encodeRequest(
            SocksRequest(SocksProtocol.COMMAND_UDP_ASSOCIATE, SocksDestination.Ip(loopback), 0)))
        output.flush()
        // Two replies precede the relay address: the 2-byte method selection, the 2-byte
        // RFC1929 sub-negotiation status, then the 4-byte reply header whose ATYP selects the
        // address length. Reading them as one header would misread ATYP and stall.
        val greeting = readFully(control, 4, "udp method/auth reply")
        if (greeting[0].toInt() != 5 || greeting[1].toInt() != 2 || greeting[3].toInt() != 0) {
            throw IOException("udp authentication failed: ${greeting.contentToString()}")
        }
        val reply = reply(control)
        if (reply[1].toInt() != 0) throw IOException("UDP_ASSOCIATE rejected: code=${reply[1].toInt()}")
        val relay = InetSocketAddress(InetAddress.getByAddress(reply.copyOfRange(4, 8)),
            ((reply[8].toInt() and 255) shl 8) or (reply[9].toInt() and 255))
        val datagrams = DatagramSocket(0, loopback).apply { soTimeout = UDP_TIMEOUT_MILLIS }
        return UdpLink(control, relay, datagrams)
    }

    private fun reply(socket: Socket): ByteArray {
        val header = readFully(socket, 4, "reply header")
        return header + readFully(socket, if (header[3].toInt() == 1) 6 else 18, "reply address")
    }

    private inner class UdpLink(
        val control: Socket,
        val relay: InetSocketAddress,
        val datagrams: DatagramSocket
    ) : AutoCloseable {
        fun roundTrip(targetPort: Int, payload: ByteArray): Boolean {
            val encoded = SocksProtocol.encodeUdpRequest(SocksUdpRequest(SocksDestination.Ip(loopback), targetPort, payload))
            datagrams.send(DatagramPacket(encoded, encoded.size, relay))
            val packet = DatagramPacket(ByteArray(MAX_DATAGRAM), MAX_DATAGRAM)
            try {
                datagrams.receive(packet)
            } catch (_: SocketTimeoutException) {
                return false
            }
            val request = SocksProtocol.decodeUdpRequest(packet.data, length = packet.length) ?: return false
            return request.payload.contentEquals(payload)
        }

        override fun close() {
            runCatching { control.close() }
            runCatching { datagrams.close() }
        }
    }

    // ---- echo targets ----

    /** Single nonblocking echo owner, independent of the forwarding event loops. */
    private inner class TcpEchoServer : AutoCloseable {
        private val selector = Selector.open()
        private val listener = ServerSocketChannel.open().apply {
            configureBlocking(false)
            bind(InetSocketAddress(loopback, 0), 1024)
            register(selector, SelectionKey.OP_ACCEPT)
        }
        val port = (listener.localAddress as InetSocketAddress).port
        private val stopped = AtomicBoolean()
        private val error = AtomicReference<Throwable>()
        private val worker = thread(name = "nio505-echo", isDaemon = true) { run() }

        private fun run() {
            try {
                while (!stopped.get()) {
                    selector.select(200)
                    val keys = selector.selectedKeys().iterator()
                    while (keys.hasNext()) {
                        val key = keys.next()
                        keys.remove()
                        if (!key.isValid) continue
                        if (key.isAcceptable) {
                            // Bounded burst per pass so a 1024-connection attach cannot starve reads.
                            var accepted = 0
                            while (accepted < ACCEPTS_PER_PASS) {
                                val channel = listener.accept() ?: break
                                channel.configureBlocking(false)
                                channel.socket().tcpNoDelay = true
                                channel.register(selector, SelectionKey.OP_READ, ByteBuffer.allocate(ECHO_BUFFER))
                                accepted++
                            }
                            continue
                        }
                        val channel = key.channel() as SocketChannel
                        val buffer = key.attachment() as ByteBuffer
                        try {
                            if (key.isReadable && buffer.hasRemaining()) {
                                if (channel.read(buffer) < 0) {
                                    key.cancel()
                                    channel.close()
                                    continue
                                }
                            }
                            if (buffer.position() > 0) {
                                buffer.flip()
                                while (buffer.hasRemaining()) if (channel.write(buffer) <= 0) break
                                buffer.compact()
                            }
                            key.interestOps(if (buffer.position() > 0) SelectionKey.OP_WRITE else SelectionKey.OP_READ)
                        } catch (_: IOException) {
                            key.cancel()
                            runCatching { channel.close() }
                        }
                    }
                }
            } catch (error: Throwable) {
                if (!stopped.get()) this.error.set(error)
            } finally {
                runCatching { selector.keys().toList().forEach { it.channel().close() } }
                runCatching { selector.close() }
            }
        }

        override fun close() {
            stopped.set(true)
            runCatching { selector.wakeup() }
            runCatching { listener.close() }
            worker.join(TimeUnit.SECONDS.toMillis(5))
            error.get()?.let { throw it }
        }
    }

    private inner class UdpEchoServer : AutoCloseable {
        private val socket = DatagramSocket(0, loopback).apply { soTimeout = 500 }
        val port = socket.localPort
        private val stopped = AtomicBoolean()
        private val error = AtomicReference<Throwable>()
        private val worker = thread(name = "nio505-udp-echo", isDaemon = true) {
            val buffer = ByteArray(MAX_DATAGRAM)
            try {
                while (!stopped.get()) {
                    try {
                        val packet = DatagramPacket(buffer, buffer.size)
                        socket.receive(packet)
                        socket.send(DatagramPacket(packet.data, packet.length, packet.socketAddress))
                    } catch (_: SocketTimeoutException) {
                        // idle tick, keeps the stop flag observable
                    } catch (error: Throwable) {
                        if (!stopped.get()) this@UdpEchoServer.error.set(error)
                        break
                    }
                }
            } finally {
                runCatching { socket.close() }
            }
        }

        override fun close() {
            stopped.set(true)
            runCatching { socket.close() }
            worker.join(TimeUnit.SECONDS.toMillis(5))
            error.get()?.let { throw it }
        }
    }

    // ---- assertions and utilities ----

    /**
     * [SocksNioServer.stop] returns once every loop reached TERMINATED, but a loop's thread object
     * only clears isAlive after its last finally block, a few instructions later. Sampling the very
     * first stats after close() therefore races a thread that is exiting with one that leaked: poll a
     * bounded window so an exiting thread passes while a stuck thread still fails, instead of
     * asserting an instantaneous zero.
     */
    private fun awaitCleanStats(server: DirectSocks5Server, label: String): SocksNioTcpServer.Stats {
        val deadline = System.nanoTime() + TimeUnit.SECONDS.toNanos(CLEANUP_SECONDS)
        var stats = checkNotNull(server.nioStats()) { "$label: no nio stats" }
        var violations = cleanViolations(stats)
        while (violations.isNotEmpty() && System.nanoTime() < deadline) {
            Thread.sleep(2)
            stats = checkNotNull(server.nioStats()) { "$label: no nio stats" }
            violations = cleanViolations(stats)
        }
        assertTrue("$label not clean after ${CLEANUP_SECONDS}s: ${violations.joinToString("; ")}",
            violations.isEmpty())
        return stats
    }

    private fun cleanViolations(stats: SocksNioTcpServer.Stats): List<String> {
        val problems = ArrayList<String>()
        fun expect(name: String, actual: Long, expected: Long) {
            if (actual != expected) problems.add("$name=$actual expected=$expected")
        }
        expect("state", if (stats.server.state == SocksNioServer.State.STOPPED) 0 else 1, 0)
        expect("eventLoopThreadsAlive", stats.eventLoopThreadsAlive.toLong(), 0)
        expect("reservedBytes", stats.buffers?.reservedBytes?.toLong() ?: -1, 0)
        expect("allocatedBytes", stats.buffers?.allocatedBytes?.toLong() ?: -1, 0)
        if (stats.server.admission == null) problems.add("missing admission stats")
        stats.server.admission?.let { admission ->
            expect("tcpLeases", admission.tcp.current.toLong(), 0)
            expect("udpLeases", admission.udp.current.toLong(), 0)
            expect("handshakeLeases", admission.handshakes.current.toLong(), 0)
            expect("pendingReservations", admission.pendingReservations.toLong(), 0)
        }
        stats.server.loops.forEachIndexed { index, loop ->
            expect("loop$index.channels", loop.channels.toLong(), 0)
            expect("loop$index.resources", loop.resources.toLong(), 0)
            expect("loop$index.timers", loop.timers.toLong(), 0)
        }
        if (stats.udp == null) problems.add("missing UDP stats")
        stats.udp?.let { udp ->
            expect("udpAssociations", udp.associations.toLong(), 0)
            expect("udpQueuedPackets", udp.queuedPackets.toLong(), 0)
            expect("udpScratchBytes", udp.scratchBytes.toLong(), 0)
        }
        return problems
    }

    private fun readFully(socket: Socket, count: Int, label: String): ByteArray {
        val buffer = ByteArray(count)
        var offset = 0
        while (offset < count) {
            val read = socket.getInputStream().read(buffer, offset, count - offset)
            if (read < 0) throw IOException("unexpected EOF reading $label ($offset/$count)")
            offset += read
        }
        return buffer
    }

    private fun await(label: String, condition: () -> Boolean) {
        val deadline = System.nanoTime() + TimeUnit.SECONDS.toNanos(AWAIT_SECONDS)
        while (!condition()) {
            assertTrue("$label: condition not met within ${AWAIT_SECONDS}s", System.nanoTime() < deadline)
            Thread.sleep(2)
        }
    }

    /**
     * Nearest-rank percentiles: P95 of n samples is index ceil(0.95n)-1, never an out-of-range floor.
     * Samples are collected and reported in nanoseconds, matching the p50Ns/p95Ns
     * CSV columns and the 20ms P95 allowance in the recorded NIO-505 comparison.
     */
    private fun percentiles(queue: ConcurrentLinkedQueue<Long>): Pair<Long, Long> {
        if (queue.isEmpty()) return 0L to 0L
        val sorted = queue.sorted()
        return percentile(sorted, 0.50) to percentile(sorted, 0.95)
    }

    private fun percentile(sorted: List<Long>, fraction: Double): Long {
        val index = Math.ceil(fraction * sorted.size).toInt() - 1
        return sorted[index.coerceIn(0, sorted.size - 1)]
    }

    private fun isResourceExhaustion(error: Throwable): Boolean {
        var current: Throwable? = error
        while (current != null) {
            val text = (current.message ?: "") + " " + current
            if (text.contains("Too many open files", ignoreCase = true) || text.contains("EMFILE") ||
                text.contains("ENFILE") || text.contains("No buffer space") ||
                text.contains("Address already in use") || current is OutOfMemoryError) return true
            current = current.cause
        }
        return false
    }

    private fun rootMessage(error: Throwable): String {
        var current: Throwable? = error
        while (current?.cause != null) current = current.cause
        return (current?.message ?: current?.toString() ?: "unknown") + " [" + error::class.simpleName + "]"
    }

    private data class Load(
        val bytes: Long,
        val latencies: ConcurrentLinkedQueue<Long>,
        val elapsedNanos: Long,
        val roundTrips: Long,
        val lost: Long,
        /** Process Java threads sampled while the load was live (drivers included). */
        val loadThreads: Int,
        /** Same, sampled after the drivers joined: server-side threads only. */
        val processThreads: Int
    )

    private data class TierResult(
        val kind: String, val tier: String, val status: String,
        val alive: Int, val sentBytes: Long, val recvBytes: Long,
        val sentBps: Double, val recvBps: Double,
        val p50Ns: Long, val p95Ns: Long,
        val processThreads: Int, val eventLoopThreads: Int,
        val stopMs: Long, val note: String
    )

    private fun writeCsv(result: TierResult) {
        val file = File(CSV_PATH)
        file.parentFile?.mkdirs()
        val line = listOf(result.kind, result.tier, result.status, result.alive,
            result.sentBytes, result.recvBytes, fmt(result.sentBps, 0), fmt(result.recvBps, 0),
            result.p50Ns, result.p95Ns, result.processThreads, result.eventLoopThreads, result.stopMs,
            "\"${result.note}\"").joinToString(",")
        if (!file.exists()) file.appendText(CSV_HEADER + "\n")
        file.appendText(line + "\n")
        synchronized(recorded) { recorded.add(result) }
        println("NIO-505 $line")
    }

    companion object {
        // Gradle test workers run with app/ as the working directory, so this lands in
        // app/build/nio-505-matrix.csv (ignored), not the repository-level build directory.
        private const val CSV_PATH = "build/nio-505-matrix.csv"
        private const val CSV_HEADER =
            "kind,tier,status,alive,sentBytes,recvBytes,sentBps,recvBps,p50Ns,p95Ns,processThreads,eventLoopThreads,stopMs,note"
        private const val TIER_PAYLOAD = 1024
        private const val UDP_PAYLOAD = 512
        private const val MAX_DATAGRAM = 65_535
        private const val DRIVER_THREADS = 16
        private const val ACCEPTS_PER_PASS = 32
        private const val ECHO_BUFFER = 16 * 1024
        private const val MAX_SAMPLES = 200_000
        private const val AUTH_LIMIT = 64
        private const val MAX_CONSECUTIVE_MISSES = 5
        private const val SOCKET_TIMEOUT_MILLIS = 10_000
        private const val UDP_TIMEOUT_MILLIS = 2_000
        private const val AWAIT_SECONDS = 30L
        private const val IDLE_WINDOW_MILLIS = 4_000L
        private const val IDLE_TURN_LIMIT = 50L
        private const val LOAD_JOIN_GRACE_SECONDS = 30L
        private const val STOP_LIMIT_MILLIS = 5_000L
        private const val CLEANUP_SECONDS = 5L
        /** No per-session Java relay thread: 1024 sessions may not add anything like 960 threads. */
        private const val THREAD_DELTA_SLACK = 8
        private val recorded = mutableListOf<TierResult>()

        @JvmStatic
        @BeforeClass
        fun resetCsv() {
            // Appending to a stale matrix from an earlier run would mix two machines' samples.
            File(CSV_PATH).delete()
        }

        @JvmStatic
        @AfterClass
        fun summarize() {
            val tiers = synchronized(recorded) { recorded.toList() }
            val tcp = tiers.filter { it.kind == "TCP" && it.status == "OK" }
            val tcp64 = tcp.firstOrNull { it.tier == "64" }
            val tcp1024 = tcp.firstOrNull { it.tier == "1024" }
            println("NIO-505 SUMMARY")
            tiers.forEach {
                println("NIO-505  ${it.kind}/${it.tier} ${it.status} alive=${it.alive} " +
                    "sentBps=${fmt(it.sentBps, 0)} p50ns=${it.p50Ns} p95ns=${it.p95Ns} " +
                    "procThreads=${it.processThreads} evLoop=${it.eventLoopThreads} stopMs=${it.stopMs}")
            }
            if (tcp64 != null && tcp1024 != null) {
                val delta = tcp1024.processThreads - tcp64.processThreads
                println("NIO-505 thread delta 1024-64 = $delta")
                // Driver threads are fixed at DRIVER_THREADS for every tier, so a correct NIO server
                // shows no growth here; BLOCKING would add ~2 threads per extra session.
                assertTrue("thread delta 1024-64 = $delta exceeds +$THREAD_DELTA_SLACK; " +
                    "per-session threads reappeared (64=${tcp64.processThreads}, " +
                    "1024=${tcp1024.processThreads})", delta <= THREAD_DELTA_SLACK)
            } else {
                println("NIO-505 thread delta 1024-64 = NOT_RAN (tier missing)")
            }
            val overLimit = tcp.filter { it.stopMs > STOP_LIMIT_MILLIS }
            assertTrue("stop over ${STOP_LIMIT_MILLIS}ms: ${overLimit.map { it.tier to it.stopMs }}",
                overLimit.isEmpty())
        }

        private fun fmt(value: Double, digits: Int) = String.format(Locale.ROOT, "%.${digits}f", value)
    }
}
