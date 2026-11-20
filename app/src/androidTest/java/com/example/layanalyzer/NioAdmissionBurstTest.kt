// Copyright (c) 2026 cheig; GPL-3.0.
package com.example.layanalyzer

import android.content.Context
import android.net.ConnectivityManager
import android.os.SystemClock
import androidx.test.core.app.ApplicationProvider
import androidx.test.platform.app.InstrumentationRegistry
import com.example.layanalyzer.capture.DirectSocks5Server
import com.example.layanalyzer.capture.SocksCredentials
import java.io.DataInputStream
import java.io.File
import java.net.InetAddress
import java.net.InetSocketAddress
import java.net.Socket
import java.util.Collections
import java.util.concurrent.CountDownLatch
import java.util.concurrent.atomic.AtomicReference
import kotlin.concurrent.thread
import org.json.JSONObject
import org.junit.Assert.*
import org.junit.Assume.assumeTrue
import org.junit.Test

/** Production admission, fixed-rate and burst arrivals on Android's sockets.
 * The independent host owns the TCP echo origin; existing sessions must survive
 * authentication saturation and remain usable after rejected clients disconnect.
 */
class NioAdmissionBurstTest {
    @Test fun authenticationStormAndPacedArrivalsPreserveEstablishedConnections() {
        val args = InstrumentationRegistry.getArguments()
        val runId = args.getString("nio601RunId")
        assumeTrue("Opt-in controlled device acceptance", runId != null)
        require(requireNotNull(runId).matches(Regex("[a-f0-9]{32}")))
        NativeTestSupport.awaitApplicationEngine()
        val context = ApplicationProvider.getApplicationContext<Context>()
        val network = requireNotNull(context.getSystemService(ConnectivityManager::class.java).activeNetwork)
        val address = InetAddress.getByName(requireNotNull(args.getString("hostGateway")))
        val origin = requireNotNull(args.getString("hostTcpPort")).toInt()
        val server = DirectSocks5Server(prepareTcp = { network.bindSocket(it); it.tcpNoDelay = true },
            prepareUdp = {}, resolveHost = { network.getAllByName(it) },
            generateCredentials = { SocksCredentials.of("u", "p") },
            runtimeLimits = com.example.layanalyzer.capture.socks.SocksRuntimeLimits(
                BuildConfig.SOCKS_TCP_LIMIT, BuildConfig.SOCKS_UDP_LIMIT, BuildConfig.SOCKS_AUTH_LIMIT))
        val out = File(context.getExternalFilesDir(null), "nio-601/$runId").apply { mkdirs() }
        val sampler = ProcessResourceSampler(File(out, "admission-burst.jsonl"), runId,
            sessions = { server.sessionStats() })
        val existing = mutableListOf<Socket>()
        val pending = Collections.synchronizedList(mutableListOf<Socket>())
        val drivers = mutableListOf<Thread>()
        val failure = AtomicReference<Throwable>()
        fun connect() = Socket().apply {
            soTimeout = 3000
            tcpNoDelay = true
            connect(InetSocketAddress("127.0.0.1", server.port), 3000)
        }
        fun established(): Socket = connect().also { peer ->
            try {
                peer.getOutputStream().write(byteArrayOf(5, 1, 2, 1, 1, 117, 1, 112, 5, 1, 0, 1) +
                    address.address + byteArrayOf((origin ushr 8).toByte(), origin.toByte()))
                val input = DataInputStream(peer.getInputStream())
                assertEquals(0x0502, input.readUnsignedShort())
                assertEquals(0x0100, input.readUnsignedShort())
                assertEquals(0x0500, input.readUnsignedShort())
                input.readUnsignedByte()
                val size = when (input.readUnsignedByte()) { 1 -> 4; 4 -> 16; else -> error("SOCKS address") }
                input.readFully(ByteArray(size + 2))
            } catch (error: Throwable) { peer.close(); throw error }
        }
        fun echo(peer: Socket) {
            val body = byteArrayOf(6, 0, 1, 44)
            peer.getOutputStream().write(body)
            val reply = ByteArray(body.size)
            DataInputStream(peer.getInputStream()).readFully(reply)
            assertArrayEquals(body, reply)
        }
        fun await(condition: () -> Boolean) {
            val deadline = SystemClock.elapsedRealtime() + 5000
            while (!condition()) {
                check(SystemClock.elapsedRealtime() < deadline) { "Admission state timed out" }
                SystemClock.sleep(5)
            }
        }
        try {
            server.start()
            repeat(8) { existing += established().also(::echo) }
            sampler.sample("established")
            val go = CountDownLatch(1)
            repeat(8) { driver ->
                drivers += thread(name = "nio601-arrival-$driver", isDaemon = true) {
                    try { go.await(); repeat(BuildConfig.SOCKS_AUTH_LIMIT * 2 / 8) { pending += connect() } }
                    catch (error: Throwable) { failure.compareAndSet(null, error) }
                }
            }
            val burstStart = SystemClock.elapsedRealtime()
            go.countDown()
            drivers.forEach { it.join(5000) }
            assertTrue(drivers.none { it.isAlive })
            failure.get()?.let { throw it }
            await { server.sessionStats().handshakes.current == BuildConfig.SOCKS_AUTH_LIMIT && server.sessionStats().rejectedHandshakes == BuildConfig.SOCKS_AUTH_LIMIT.toLong() }
            val burstMs = SystemClock.elapsedRealtime() - burstStart
            assertTrue("burst must precede handshake expiry", burstMs < 5000)
            existing.forEach(::echo)
            val burst = sampler.sample("configured_arrival_burst")
            pending.forEach { it.close() }
            pending.clear()
            await { server.sessionStats().handshakes.current == 0 }
            val pacedStart = SystemClock.elapsedRealtime()
            repeat(BuildConfig.SOCKS_AUTH_LIMIT) { index ->
                val due = pacedStart + index * 1000 / 32
                val pause = due - SystemClock.elapsedRealtime()
                if (pause > 0) SystemClock.sleep(pause)
                pending += connect()
            }
            await { server.sessionStats().handshakes.current == BuildConfig.SOCKS_AUTH_LIMIT }
            assertEquals(BuildConfig.SOCKS_AUTH_LIMIT.toLong(), server.sessionStats().rejectedHandshakes)
            existing.forEach(::echo)
            val paced = sampler.sample("32_per_second_configured_held")
            pending.forEach { it.close() }
            pending.clear()
            await { server.sessionStats().handshakes.current == 0 }
            established().use(::echo)
            val stopStart = SystemClock.elapsedRealtime()
            server.close()
            val stopMs = SystemClock.elapsedRealtime() - stopStart
            assertTrue(stopMs <= 5000)
            assertEquals(0, server.sessionStats().tcp.current)
            assertEquals(0, server.sessionStats().handshakes.current)
            sampler.sample("stopped")
            File(out, "admission-burst-result.json").writeText(JSONObject().put("status", "PASS")
                .put("burstArrivals", BuildConfig.SOCKS_AUTH_LIMIT * 2).put("burstMs", burstMs).put("refusedAtAuthentication", BuildConfig.SOCKS_AUTH_LIMIT)
                .put("pacedArrivalsPerSecond", 32).put("existingConnectionsPreserved", 8)
                .put("burst", burst).put("paced", paced).put("stopMs", stopMs).toString(2))
        } finally {
            drivers.forEach { it.interrupt(); it.join(5000) }
            pending.forEach { runCatching { it.close() } }
            existing.forEach { runCatching { it.close() } }
            server.close()
            sampler.close()
        }
    }
}
