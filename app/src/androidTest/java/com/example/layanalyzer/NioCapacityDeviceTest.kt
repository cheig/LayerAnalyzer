// Copyright (c) 2026 cheig; GPL-3.0.
package com.example.layanalyzer

import android.content.Context
import android.os.SystemClock
import android.util.Log
import androidx.test.core.app.ApplicationProvider
import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.platform.app.InstrumentationRegistry
import com.example.layanalyzer.capture.DirectSocks5Server
import com.example.layanalyzer.capture.SocksCredentials
import com.example.layanalyzer.capture.SocksDestination
import com.example.layanalyzer.capture.SocksRequest
import com.example.layanalyzer.capture.UdpDestinationPolicy
import com.example.layanalyzer.capture.socks.SocksNioServer
import com.example.layanalyzer.capture.socks.SocksProtocol
import com.example.layanalyzer.capture.socks.SocksRuntimeLimits
import java.io.DataInputStream
import java.io.File
import java.io.IOException
import java.net.InetAddress
import java.net.InetSocketAddress
import java.net.Socket
import java.nio.ByteBuffer
import java.nio.channels.SelectionKey
import java.nio.channels.Selector
import java.nio.channels.ServerSocketChannel
import java.nio.channels.SocketChannel
import java.util.UUID
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicBoolean
import java.util.concurrent.atomic.AtomicLong
import java.util.concurrent.atomic.AtomicReference
import kotlin.concurrent.thread
import org.json.JSONObject
import org.junit.After
import org.junit.Before
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Assume.assumeTrue
import org.junit.Test
import org.junit.runner.RunWith

/**
 * NIO-505 device-side minimum evidence: the two items the plan's §11.2 matrix can still be
 * measured for on this device without a host fixture.
 *
 * 1. Twenty capture start/stop cycles must return FD, thread and PSS to an explainable baseline
 *    (§11.3: "20 次启停后的 FD 回到可解释的基线范围").
 * 2. One 64-session tier held for a real, configurable window must not add per-session Java relay
 *    threads and must stop inside 5 seconds (§11.2 item 1 minimum hold, §11.3 stop target).
 *
 * This drives the real production `DirectSocks5Server` NIO facade over loopback, but it is NOT the
 * full-VPN device matrix: no TUN/HEV path, no TLS gateway, no 5-minute-per-tier sweep up to 1024,
 * no 30-minute mixed soak. Those stay NOT_RUN in candidate device validation remains NOT_RUN
 *
 * Opt-in: the 64-session hold costs `nio505HoldSeconds` (default 300s) and the restart test costs
 * `nio505Cycles` (default 20). Both are instrumentation arguments, so a plain
 * `connectedDebugAndroidTest` run stays short unless the arguments are passed.
 */
@RunWith(AndroidJUnit4::class)
class NioCapacityDeviceTest {
    private val context = ApplicationProvider.getApplicationContext<Context>()
    private val args = InstrumentationRegistry.getArguments()
    private val loopback = InetAddress.getByAddress(byteArrayOf(127, 0, 0, 1))
    private val directory = File(context.getExternalFilesDir(null) ?: context.filesDir, "nio-505-device")
        .apply { mkdirs() }
    private var server: DirectSocks5Server? = null
    private val optedIn = args.getString("nio505DeviceRun") != null

    @Before fun keepLoadRunnable() {
        if (!optedIn) return
        NativeTestSupport.awaitApplicationEngine()
    }

    @After
    fun stopServer() {
        runCatching { server?.close() }
        server = null
    }

    /** §11.2 item 6 / §11.3: twenty restarts must not leave FD, threads or PSS drifting upward. */
    @Test
    fun twentyRestartCyclesKeepResourcesAtBaseline() {
        assumeTrue("Opt-in NIO-505 device capacity fixture", optedIn)
        val cycles = args.getString("nio505Cycles")?.toIntOrNull() ?: RESTART_CYCLES
        val echo = TcpEchoTarget()
        val sampler = sampler("restart")
        try {
            // Warm ART/JIT and the native SOCKS paths so the baseline is steady state, not the
            // cold-start footprint of the first server.
            repeat(WARMUP_CYCLES) { restartCycle(echo) }
            SystemClock.sleep(SETTLE_MILLIS)
            val baseline = sampler.sample("baseline")
            val stops = ArrayList<Long>()
            val rows = ArrayList<JSONObject>()
            repeat(cycles) { index ->
                stops += restartCycle(echo)
                SystemClock.sleep(SETTLE_MILLIS)
                rows += sampler.sample("after_cycle_${index + 1}")
            }
            val last = rows.last()
            Log.i(TAG, "restart cycles=$cycles baseline fds=${baseline.fds()} threads=${baseline.threads()} " +
                "pssKiB=${baseline.pss()} last fds=${last.fds()} threads=${last.threads()} pssKiB=${last.pss()}")
            assertTrue("stop over ${STOP_LIMIT_MILLIS}ms: ${stops.filter { it > STOP_LIMIT_MILLIS }}",
                stops.all { it <= STOP_LIMIT_MILLIS })
            assertTrue("fd drift baseline=${baseline.fds()} last=${last.fds()}",
                last.fds() <= baseline.fds() + FD_SLACK)
            assertTrue("thread drift baseline=${baseline.threads()} last=${last.threads()}",
                last.threads() <= baseline.threads() + THREAD_SLACK)
            // A trend, not a single GC: compare the first and last quarter of the cycles.
            val quarter = maxOf(1, cycles / 4)
            val early = rows.take(quarter).map { it.pss() }.average()
            val late = rows.takeLast(quarter).map { it.pss() }.average()
            Log.i(TAG, "restart pss trend earlyKiB=$early lateKiB=$late")
            assertTrue("pss trend earlyKiB=$early lateKiB=$late",
                late <= early + PSS_SLACK_KIB)
        } finally {
            runCatching { echo.close() }
            sampler.close()
        }
    }

    /** §11.2 item 1 minimum hold / §11.3: 64 sessions, fixed threads, stop inside 5s, then zero. */
    @Test
    fun tcp64HoldKeepsFixedThreadsAndStops() {
        assumeTrue("Opt-in NIO-505 device capacity fixture", optedIn)
        val holdSeconds = args.getString("nio505HoldSeconds")?.toLongOrNull() ?: HOLD_SECONDS
        val echo = TcpEchoTarget()
        val sampler = sampler("hold")
        val clients = ArrayList<Socket>(TCP_SESSIONS)
        val live = newServer(TCP_SESSIONS)
        server = live
        try {
            val baseline = sampler.sample("baseline")
            val port = live.start(0)
            repeat(TCP_SESSIONS) { clients += socksConnect(live, port, echo.port) }
            await("tcp admission $TCP_SESSIONS") { live.sessionStats().tcp.current == TCP_SESSIONS }
            val established = sampler.sample("established")
            val rtts = AtomicLong()
            val bytes = AtomicLong()
            val failures = AtomicReference<Throwable>()
            val deadline = SystemClock.elapsedRealtimeNanos() + TimeUnit.SECONDS.toNanos(holdSeconds)
            // Fixed driver pool rotating over every connection: the tier number is real only when
            // all of it keeps transferring, and the pool size never scales with the session count.
            val drivers = (0 until DRIVER_THREADS).map { index ->
                thread(name = "nio505-dev-$index", isDaemon = true) {
                    try {
                        val slice = clients.subList(index * clients.size / DRIVER_THREADS,
                            (index + 1) * clients.size / DRIVER_THREADS)
                        while (SystemClock.elapsedRealtimeNanos() < deadline && failures.get() == null) {
                            for (client in slice) {
                                if (SystemClock.elapsedRealtimeNanos() >= deadline) break
                                echoRoundTrip(client)
                                rtts.incrementAndGet()
                                bytes.addAndGet(2L * PAYLOAD_SIZE)
                            }
                        }
                    } catch (error: Throwable) {
                        failures.compareAndSet(null, error)
                    }
                }
            }
            val holdStart = SystemClock.elapsedRealtimeNanos()
            var peakFds = established.fds()
            var peakThreads = established.threads()
            var samples = 0
            var previousSample = holdStart
            while (SystemClock.elapsedRealtimeNanos() < deadline) {
                SystemClock.sleep(SAMPLE_MILLIS)
                val row = sampler.sample("hold")
                val sampled = SystemClock.elapsedRealtimeNanos()
                assertTrue("Sampling gap indicates a paused or stalled load",
                    sampled - previousSample < TimeUnit.SECONDS.toNanos(15))
                previousSample = sampled
                samples++
                peakFds = maxOf(peakFds, row.fds())
                peakThreads = maxOf(peakThreads, row.threads())
                assertEquals("sessions held", TCP_SESSIONS, live.sessionStats().tcp.current)
            }
            drivers.forEach { it.join(TimeUnit.SECONDS.toMillis(60)) }
            assertTrue("driver thread still running", drivers.none { it.isAlive })
            failures.get()?.let { throw it }
            val seconds = (SystemClock.elapsedRealtimeNanos() - holdStart) / 1_000_000_000.0
            val stats = requireNotNull(live.nioStats())
            assertEquals("event loop threads", 2, stats.eventLoopThreadsAlive)
            assertEquals("admitted tcp", TCP_SESSIONS, requireNotNull(stats.server.admission).tcp.current)
            val fdDelta = peakFds - baseline.fds()
            val threadDelta = peakThreads - baseline.threads()
            Log.i(TAG, "hold seconds=${"%.1f".format(seconds)} rtts=${rtts.get()} bytes=${bytes.get()} " +
                "samples=$samples baseline fds=${baseline.fds()} threads=${baseline.threads()} " +
                "peak fds=$peakFds threads=$peakThreads fdDelta=$fdDelta threadDelta=$threadDelta " +
                "pssKiB=${established.pss()}")
            // Fixed cost: two event loops plus the fixed driver pool and this sampler. A BLOCKING
            // server would need roughly two threads per session here (128 for 64 sessions).
            assertTrue("threads grew with sessions: delta=$threadDelta " +
                "(baseline=${baseline.threads()} peak=$peakThreads)",
                threadDelta <= DRIVER_THREADS + 2 + THREAD_SLACK)
            assertTrue("fd delta $fdDelta exceeds a bounded per-session cost",
                fdDelta <= FD_PER_SESSION * TCP_SESSIONS + FD_SLACK)
            val started = SystemClock.elapsedRealtimeNanos()
            clients.forEach { runCatching { it.close() } }
            clients.clear()
            live.close()
            val stopMs = TimeUnit.NANOSECONDS.toMillis(SystemClock.elapsedRealtimeNanos() - started)
            Log.i(TAG, "hold stopMs=$stopMs")
            assertTrue("stop took ${stopMs}ms", stopMs <= STOP_LIMIT_MILLIS)
            assertClean(live)
            val final = live.sessionStats()
            assertEquals("tcp leases after stop", 0, final.tcp.current)
            assertEquals("udp leases after stop", 0, final.udp.current)
            assertEquals("handshake leases after stop", 0, final.handshakes.current)
            assertEquals("tcp rejections", 0L, final.rejectedTcp)
            assertEquals("udp rejections", 0L, final.rejectedUdp)
            sampler.sample("after_stop")
        } finally {
            clients.forEach { runCatching { it.close() } }
            runCatching { echo.close() }
            sampler.close()
        }
    }

    // ---- server and clients ----

    private fun newServer(tcp: Int = 64, udp: Int = 64): DirectSocks5Server = DirectSocks5Server(
        // Loopback only: no VPN is active, so there is no route to protect and no physical
        // network to bind. The real protect/bind ordering is covered by NioChannelProtectionTest.
        prepareTcp = { it.tcpNoDelay = true },
        prepareUdp = {},
        resolveHost = { arrayOf(loopback) },

        generateCredentials = { SocksCredentials.generate() },
        tlsGateway = null,
        udpPolicy = UdpDestinationPolicy.PRESERVE,
        runtimeLimits = SocksRuntimeLimits(tcp, udp, AUTH_LIMIT)
    )

    /** One full start/authenticate/forward/stop cycle; returns the measured stop duration. */
    private fun restartCycle(echo: TcpEchoTarget): Long {
        val live = newServer().also { server = it }
        val stopMs: Long
        try {
            val port = live.start(0)
            val client = socksConnect(live, port, echo.port)
            try {
                echoRoundTrip(client)
            } finally {
                runCatching { client.close() }
            }
            val started = SystemClock.elapsedRealtimeNanos()
            live.close()
            stopMs = TimeUnit.NANOSECONDS.toMillis(SystemClock.elapsedRealtimeNanos() - started)
            assertClean(live)
            val stats = live.sessionStats()
            assertEquals("cycle tcp leases", 0, stats.tcp.current)
            assertEquals("cycle handshake leases", 0, stats.handshakes.current)
        } finally {
            // close() is idempotent; this only covers the failure paths above.
            runCatching { live.close() }
        }
        return stopMs
    }

    private fun socksConnect(live: DirectSocks5Server, port: Int, targetPort: Int): Socket {
        val socket = Socket()
        try {
            socket.soTimeout = SOCKET_TIMEOUT_MILLIS
            socket.tcpNoDelay = true
            socket.connect(InetSocketAddress(loopback, port), SOCKET_TIMEOUT_MILLIS)
            val credentials = live.credentials
            val user = credentials.username.toByteArray(Charsets.US_ASCII)
            val password = credentials.password.toByteArray(Charsets.US_ASCII)
            val output = socket.getOutputStream()
            output.write(byteArrayOf(5, 1, 2))
            output.write(byteArrayOf(1, user.size.toByte()) + user + byteArrayOf(password.size.toByte()) + password)
            output.write(SocksProtocol.encodeRequest(SocksRequest(SocksProtocol.COMMAND_CONNECT,
                SocksDestination.Ip(loopback), targetPort)))
            output.flush()
            val input = DataInputStream(socket.getInputStream())
            check(input.readUnsignedShort() == 0x0502) { "SOCKS_METHOD_REPLY" }
            check(input.readUnsignedShort() == 0x0100) { "SOCKS_AUTH_REPLY" }
            check(input.readUnsignedShort() == 0x0500) { "SOCKS_CONNECT_REPLY" }
            input.readUnsignedByte()
            val length = when (input.readUnsignedByte()) { 1 -> 4; 4 -> 16; else -> error("SOCKS_ATYP") }
            input.readFully(ByteArray(length))
            input.readUnsignedShort()
            return socket
        } catch (error: Throwable) {
            runCatching { socket.close() }
            throw error
        }
    }

    private fun echoRoundTrip(client: Socket) {
        val payload = ByteArray(PAYLOAD_SIZE) { (it % 251).toByte() }
        client.getOutputStream().write(payload)
        client.getOutputStream().flush()
        val echoed = ByteArray(payload.size)
        val input = DataInputStream(client.getInputStream())
        input.readFully(echoed)
        if (!echoed.contentEquals(payload)) throw IOException("TCP_ECHO_MISMATCH")
    }

    // ---- echo target: one nonblocking owner, so the thread delta stays honest ----

    private inner class TcpEchoTarget : AutoCloseable {
        private val selector = Selector.open()
        private val listener = ServerSocketChannel.open().apply {
            configureBlocking(false)
            bind(InetSocketAddress(loopback, 0), 128)
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
                            while (true) {
                                val channel = listener.accept() ?: break
                                channel.configureBlocking(false)
                                channel.socket().tcpNoDelay = true
                                channel.register(selector, SelectionKey.OP_READ, ByteBuffer.allocate(ECHO_BUFFER))
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

    // ---- assertions and helpers ----

    /**
     * `close()` returns once the owner loops have finished their cleanup, but ART may still report
     * the last loop thread as alive for a moment. Poll on a deadline instead of assuming thread
     * teardown is synchronous, then assert the zeroed state strictly.
     */
    private fun assertClean(live: DirectSocks5Server) {
        val deadline = SystemClock.elapsedRealtime() + AWAIT_MILLIS
        var snapshot = requireNotNull(live.nioStats()) { "no NIO snapshot after stop" }
        while (snapshot.eventLoopThreadsAlive != 0) {
            check(SystemClock.elapsedRealtime() < deadline) {
                "event loop threads still ${snapshot.eventLoopThreadsAlive} ${AWAIT_MILLIS}ms after stop"
            }
            SystemClock.sleep(5)
            snapshot = requireNotNull(live.nioStats())
        }
        assertEquals("state", SocksNioServer.State.STOPPED, snapshot.server.state)
        val buffers = requireNotNull(snapshot.buffers)
        assertEquals("reserved buffers", 0, buffers.reservedBytes)
        assertEquals("allocated buffers", 0, buffers.allocatedBytes)
        val admission = requireNotNull(snapshot.server.admission)
        assertEquals("tcp leases", 0, admission.tcp.current)
        assertEquals("udp leases", 0, admission.udp.current)
        assertEquals("handshake leases", 0, admission.handshakes.current)
        assertEquals("pending reservations", 0, admission.pendingReservations)
        snapshot.server.loops.forEachIndexed { index, loop ->
            assertEquals("loop$index channels", 0, loop.channels)
            assertEquals("loop$index resources", 0, loop.resources)
            assertEquals("loop$index timers", 0, loop.timers)
        }
        val udp = requireNotNull(snapshot.udp)
        assertEquals("udp associations", 0, udp.associations)
        assertEquals("udp queued packets", 0, udp.queuedPackets)
        assertEquals("udp scratch", 0, udp.scratchBytes)
    }

    private fun sampler(label: String): ProcessResourceSampler = ProcessResourceSampler(
        File(directory, "$label-${UUID.randomUUID().toString().replace("-", "")}.jsonl"),
        UUID.randomUUID().toString().replace("-", ""),
        intervalMillis = 1_000,
        // sessionStats() stays readable after close(), so a finished cycle's final snapshot is
        // still what the next sample sees.
        sessions = { server?.sessionStats() }
    )

    private fun await(label: String, condition: () -> Boolean) {
        val deadline = SystemClock.elapsedRealtime() + AWAIT_MILLIS
        while (!condition()) {
            check(SystemClock.elapsedRealtime() < deadline) { "$label: not met within ${AWAIT_MILLIS}ms" }
            SystemClock.sleep(5)
        }
    }

    private fun JSONObject.fds(): Int = getJSONObject("process").getInt("fds")
    private fun JSONObject.threads(): Int = getJSONObject("process").getInt("threads")
    private fun JSONObject.pss(): Long = getJSONObject("process").getLong("pssKiB")

    companion object {
        private const val TAG = "LayAnalyzer-Nio505"
        private const val RESTART_CYCLES = 20
        private const val WARMUP_CYCLES = 2
        private const val HOLD_SECONDS = 300L
        private const val TCP_SESSIONS = 64
        private const val AUTH_LIMIT = 64
        private const val DRIVER_THREADS = 8
        private const val PAYLOAD_SIZE = 1024
        private const val ECHO_BUFFER = 16 * 1024
        private const val SAMPLE_MILLIS = 5_000L
        private const val SETTLE_MILLIS = 500L
        private const val STOP_LIMIT_MILLIS = 5_000L
        private const val AWAIT_MILLIS = 30_000L
        private const val SOCKET_TIMEOUT_MILLIS = 10_000
        private const val FD_SLACK = 8
        private const val THREAD_SLACK = 6
        private const val PSS_SLACK_KIB = 24L * 1024
        /** Loopback direct path: accepted socket + upstream socket + one HEV-side descriptor. */
        private const val FD_PER_SESSION = 4
    }
}
