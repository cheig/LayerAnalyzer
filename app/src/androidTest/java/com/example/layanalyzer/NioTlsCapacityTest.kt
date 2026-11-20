// Copyright (c) 2026 cheig; GPL-3.0.
package com.example.layanalyzer

import android.content.Context
import android.net.ConnectivityManager
import android.net.http.X509TrustManagerExtensions
import android.os.SystemClock
import android.util.Base64
import androidx.test.core.app.ApplicationProvider
import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.platform.app.InstrumentationRegistry
import com.example.layanalyzer.capture.DirectSocks5Server
import com.example.layanalyzer.capture.socks.SocksRuntimeLimits
import com.example.layanalyzer.capture.tls.*
import com.example.layanalyzer.model.TlsCaptureSettings
import java.io.DataInputStream
import java.io.File
import java.net.InetAddress
import java.net.Socket
import java.security.KeyStore
import java.security.cert.CertificateFactory
import java.util.Collections
import java.util.concurrent.CountDownLatch
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicBoolean
import java.util.concurrent.atomic.AtomicInteger
import java.util.concurrent.atomic.AtomicLong
import java.util.concurrent.atomic.AtomicLongArray
import java.util.concurrent.atomic.AtomicReference
import javax.net.ssl.SSLContext
import javax.net.ssl.SSLSocket
import javax.net.ssl.TrustManagerFactory
import javax.net.ssl.X509TrustManager
import kotlin.concurrent.thread
import org.json.JSONObject
import org.json.JSONArray
import org.junit.Assert.*
import org.junit.Assume.assumeTrue
import org.junit.Test
import org.junit.runner.RunWith

/** Real JNI/Go/NIO and Android TLS peers. The only delayed operation is the test
 * trust callback; verification still uses Android's chain/name verifier. This is
 * gateway load evidence, not TUN capture or durable-secret evidence.
 */
@RunWith(AndroidJUnit4::class)
class NioTlsCapacityTest {
    @Test fun establishedTlsConnectionsSurviveEightPendingHandshakesAndCapacityPassthrough() = runTlsLoad(16, false)
    @Test fun compareTls32Connections() = runTlsLoad(32, true)
    @Test fun compareTls64Connections() = runTlsLoad(64, true)

    @Test fun expandedRuntimeRelays128TlsConnectionsWithoutLegacy64Ceiling() =
        runTlsLoad(128, false, expandedRuntime = true)

    private fun runTlsLoad(connections: Int, performance: Boolean, expandedRuntime: Boolean = false) {
        val args = InstrumentationRegistry.getArguments()
        val runId = args.getString("nio601RunId")
        assumeTrue("Opt-in controlled TLS origin", runId != null)
        require(requireNotNull(runId).matches(Regex("[a-f0-9]{32}")))
        assertTrue(BuildConfig.TLS_ENABLED)
        assertFalse(BuildConfig.TLS_PROBE_ENABLED)
        NativeTestSupport.awaitApplicationEngine()
        val context = ApplicationProvider.getApplicationContext<Context>()
        val host = requireNotNull(args.getString("hostGateway"))
        val port = requireNotNull(args.getString("hostTlsPort")).toInt()
        val root = Base64.decode(requireNotNull(args.getString("nio601RootDer")), Base64.NO_WRAP)
        val physical = requireNotNull(context.getSystemService(ConnectivityManager::class.java).activeNetwork)
        val bridge = TlsProxyBridge()
        val name = "upstream.fixture.test"
        val held = CountDownLatch(8)
        val release = CountDownLatch(1)
        val blockVerification = AtomicBoolean()
        val secrets = AtomicInteger()
        val verifier = AndroidUpstreamTrustVerifier(UpstreamChainVerifier { chain, auth, identity ->
            X509TrustManagerExtensions(trust(listOf(root))).checkServerTrusted(chain, auth, identity)
        })
        val protector = UpstreamSocketProtector({ UpstreamSocketProtector.NetworkSnapshot(physical, 1) }, { true })
        val callbacks = object : TlsPlatformCallbacks {
            override fun prepareSocket(fd: Int, networkGeneration: Long) = protector.prepareSocket(fd, networkGeneration)
            override fun resolveHost(host: String, networkGeneration: Long) = protector.resolveHost(host, networkGeneration)
            override fun verifyUpstream(chainDer: Array<ByteArray>, identity: String, authType: String, tlsVersion: String): String {
                if (blockVerification.get()) {
                    held.countDown()
                    check(release.await(8, TimeUnit.SECONDS)) { "FIXTURE_VERIFICATION_TIMEOUT" }
                }
                return verifier.verifyUpstream(chainDer, identity, authType, tlsVersion)
            }
            override fun offerSecret(captureId: String, connectionId: String, line: ByteArray): Boolean {
                line.fill(0)
                secrets.incrementAndGet()
                return true // Count-and-dispose test sink. Persistence is checked separately.
            }
        }
        val material = NativeEngine.generateTlsCaMaterial()
        val clients = Collections.synchronizedList(mutableListOf<SSLSocket>())
        val workers = mutableListOf<Thread>()
        val failures = AtomicReference<Throwable>()
        var handle = 0L
        var socks: DirectSocks5Server? = null
        var channel: TlsGatewayChannel? = null
        try {
            val policy = TlsRoutingPolicy.freeze(TlsCaptureSettings(enabled = true,
                candidatePorts = setOf(port), includeHosts = listOf(name)))
            val limits = if (expandedRuntime) SocksRuntimeLimits(BuildConfig.SOCKS_TCP_LIMIT,
                BuildConfig.SOCKS_UDP_LIMIT, BuildConfig.SOCKS_AUTH_LIMIT) else SocksRuntimeLimits(64, 64, 64)
            val config = JSONObject().put("schemaVersion", if (expandedRuntime) 2 else 1).put("captureId", "nio601-$runId")
                .put("networkGeneration", 1).put("settings", JSONObject(policy.encode()))
            if (expandedRuntime) config.put("socksRuntime", limits.encode())
            val started = JSONObject(bridge.start(config.toString(), material[0], material[1], callbacks))
            assertTrue(started.toString(), started.getBoolean("success"))
            handle = started.getLong("engineHandle")
            val initialStats = JSONObject(bridge.stats(handle))
            assertEquals(limits.tcp, initialStats.getJSONObject("budget").getInt("connectionLimit"))
            assertEquals(limits.authentication, initialStats.getJSONObject("gateway").getInt("authenticationLimit"))
            assertEquals(limits.tcp, initialStats.getJSONObject("gateway").getInt("activeLimit"))
            channel = TlsGatewayChannel(started.getInt("port"), bridge.gatewayToken(handle),
                "nio601-$runId", 1, policy, {})
            socks = DirectSocks5Server(prepareTcp = { error("TLS gateway must own upstream") },
                prepareUdp = {}, resolveHost = { physical.getAllByName(it) }, tlsGateway = channel, runtimeLimits = limits)
            val listener = socks.start()
            val tls = SSLContext.getInstance("TLS").apply { init(null, arrayOf(trust(listOf(material[0], root))), null) }
            fun connect(): SSLSocket {
                val raw = open(socks, listener, host, port)
                return try {
                    (tls.socketFactory.createSocket(raw, name, port, true) as SSLSocket).also { peer ->
                        clients.add(peer)
                        peer.soTimeout = 15000
                        peer.enabledProtocols = arrayOf("TLSv1.3")
                        peer.sslParameters = peer.sslParameters.apply { endpointIdentificationAlgorithm = "HTTPS" }
                        peer.startHandshake()
                        echo(peer)
                    }
                } catch (error: Throwable) { raw.close(); throw error }
            }
            repeat(connections) { connect() }
            if (performance) {
                measureTls(clients, socks, context, runId)
                val relaying = JSONObject(bridge.stats(handle))
                assertEquals(connections.toLong(), relaying.getJSONObject("events").getLong("connectionsProxied"))
                assertEquals(0L, relaying.getJSONObject("events").getLong("connectionsPassthrough"))
                socks.close()
                val stop = JSONObject(bridge.stop(handle, 5000))
                assertTrue(stop.getBoolean("success"))
                val budget = stop.getJSONObject("finalStats").getJSONObject("budget")
                assertEquals(0, budget.getInt("connections"))
                assertEquals(0, budget.getInt("handshakes"))
                File(context.getExternalFilesDir(null), "nio-601/$runId/tls-performance-${clients.size}.json").let { file ->
                    file.writeText(JSONObject(file.readText()).put("status", "PASS")
                        .put("relaying", relaying).put("stop", stop).toString(2))
                }
                return
            }
            blockVerification.set(true)
            repeat(8) {
                workers += thread(name = "nio601-tls-handshake-$it", isDaemon = true) {
                    try { connect() } catch (error: Throwable) { failures.compareAndSet(null, error) }
                }
            }
            assertTrue("eight real upstream handshakes must reach verification", held.await(6, TimeUnit.SECONDS))
            val pending = JSONObject(bridge.stats(handle))
            assertEquals(8, pending.getJSONObject("budget").getInt("handshakes"))
            assertEquals(connections + 8, pending.getJSONObject("budget").getInt("connections"))
            // Established TLS sessions must still forward while all handshake slots are held.
            clients.take(16).forEach { echo(it) }
            connect() // Ninth candidate negotiates real TLS directly with the origin.
            val saturated = JSONObject(bridge.stats(handle))
            assertEquals(1L, saturated.getJSONObject("events").getLong("handshakeCapacityPassthrough"))
            release.countDown()
            workers.forEach { it.join(15000) }
            assertTrue(workers.none { it.isAlive })
            failures.get()?.let { throw it }
            blockVerification.set(false)
            val until = SystemClock.elapsedRealtime() + 30000
            while (SystemClock.elapsedRealtime() < until) {
                clients.forEach { echo(it) }
                bridge.poll(handle, 128)
                SystemClock.sleep(1000)
            }
            val relaying = JSONObject(bridge.stats(handle))
            assertEquals(connections + 9, relaying.getJSONObject("budget").getInt("connections"))
            assertEquals(0, relaying.getJSONObject("budget").getInt("handshakes"))
            assertEquals((connections + 8).toLong(), relaying.getJSONObject("events").getLong("connectionsProxied"))
            assertEquals(1L, relaying.getJSONObject("events").getLong("connectionsPassthrough"))
            socks.close()
            val stop = JSONObject(bridge.stop(handle, 5000))
            assertTrue(stop.getBoolean("success"))
            val stopped = stop.getJSONObject("finalStats")
            assertEquals(0, stopped.getJSONObject("budget").getInt("connections"))
            assertEquals(0, stopped.getJSONObject("budget").getInt("handshakes"))
            File(context.getExternalFilesDir(null), "nio-601/$runId").apply { mkdirs() }
                .resolve("tls-capacity.json").writeText(JSONObject().put("status", "PASS")
                    .put("runtime", limits.encode()).put("expandedRuntime", expandedRuntime)
                    .put("pending", pending).put("saturated", saturated).put("relaying", relaying)
                    .put("stopped", stopped).put("discardedTestSecretRecords", secrets.get()).toString(2))
        } finally {
            release.countDown()
            synchronized(clients) { clients.forEach { runCatching { it.close() } } }
            workers.forEach { it.join(15000) }
            socks?.close()
            channel?.close()
            if (handle != 0L) bridge.stop(handle, 5000)
            material.forEach { it.fill(0) }
        }
    }

    private fun measureTls(clients: List<SSLSocket>, socks: DirectSocks5Server, context: Context, runId: String) {
        val out = File(context.getExternalFilesDir(null), "nio-601/$runId").apply { mkdirs() }
        val results = JSONArray()
        repeat(4) { round ->
            val sampler = ProcessResourceSampler(File(out, "tls-performance-${clients.size}-$round.jsonl"),
                runId, sessions = { socks.sessionStats() })
            val failure = AtomicReference<Throwable>()
            val bytes = AtomicLong()
            val latency = AtomicLongArray(32)
            val started = SystemClock.elapsedRealtimeNanos()
            val deadline = started + (if (round == 0) 3 else 15) * 1_000_000_000L
            val drivers = mutableListOf<Thread>()
            try {
                sampler.sample("before")
                repeat(8) { driver ->
                    drivers += thread(name = "nio601-tls-perf-$driver", isDaemon = true) {
                        val body = ByteArray(1024) { (it % 251).toByte() }
                        val reply = ByteArray(body.size)
                        try {
                            while (SystemClock.elapsedRealtimeNanos() < deadline && failure.get() == null) {
                                for (id in driver until clients.size step 8) {
                                    if (SystemClock.elapsedRealtimeNanos() >= deadline) break
                                    val start = SystemClock.elapsedRealtimeNanos()
                                    clients[id].getOutputStream().write(body)
                                    DataInputStream(clients[id].getInputStream()).readFully(reply)
                                    assertArrayEquals(body, reply)
                                    val micros = maxOf(1L, (SystemClock.elapsedRealtimeNanos() - start) / 1000)
                                    latency.incrementAndGet((64 - java.lang.Long.numberOfLeadingZeros(micros)).coerceAtMost(31))
                                    bytes.addAndGet(body.size * 2L)
                                }
                            }
                        } catch (error: Throwable) { failure.compareAndSet(null, error) }
                    }
                }
                SystemClock.sleep(1000)
                val held = sampler.sample("held")
                drivers.forEach { it.join(30000) }
                assertTrue("TLS load drivers must stop", drivers.none { it.isAlive })
                failure.get()?.let { throw it }
                val elapsed = SystemClock.elapsedRealtimeNanos() - started
                val total = (0 until latency.length()).sumOf { latency.get(it) }
                fun quantile(fraction: Double): Long {
                    var count = 0L
                    for (bucket in 0 until latency.length()) {
                        count += latency.get(bucket)
                        if (count >= total * fraction) return 1L shl bucket
                    }
                    error("No TLS latency samples")
                }
                assertTrue(bytes.get() > 0)
                results.put(JSONObject().put("warmup", round == 0).put("connections", clients.size)
                    .put("mode", socks.nioStats().mode).put("bytes", bytes.get()).put("elapsedNanos", elapsed)
                    .put("bytesPerSecond", bytes.get() * 1e9 / elapsed).put("p50UpperMicros", quantile(.50))
                    .put("p95UpperMicros", quantile(.95)).put("heldProcess", held.getJSONObject("process")))
            } finally {
                if (drivers.any { it.isAlive }) clients.forEach { runCatching { it.close() } }
                drivers.forEach { it.join(10000) }
                sampler.close()
            }
        }
        File(out, "tls-performance-${clients.size}.json").writeText(JSONObject().put("status", "PENDING_CLEANUP")
            .put("runId", runId).put("tlsBuilt", BuildConfig.TLS_ENABLED).put("samples", results).toString(2))
    }

    private fun trust(certificates: List<ByteArray>): X509TrustManager {
        val store = KeyStore.getInstance(KeyStore.getDefaultType()).apply {
            load(null)
            certificates.forEachIndexed { index, bytes -> setCertificateEntry("root-$index",
                CertificateFactory.getInstance("X.509").generateCertificate(bytes.inputStream())) }
        }
        return TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm()).apply { init(store) }
            .trustManagers.filterIsInstance<X509TrustManager>().single()
    }

    private fun open(server: DirectSocks5Server, listener: Int, host: String, port: Int): Socket {
        val peer = Socket("127.0.0.1", listener)
        try {
            peer.soTimeout = 15000
            val user = server.credentials.username.toByteArray(Charsets.US_ASCII)
            val password = server.credentials.password.toByteArray(Charsets.US_ASCII)
            peer.getOutputStream().write(byteArrayOf(5, 1, 2, 1, user.size.toByte()) + user +
                byteArrayOf(password.size.toByte()) + password + byteArrayOf(5, 1, 0, 1) +
                InetAddress.getByName(host).address + byteArrayOf((port ushr 8).toByte(), port.toByte()))
            val input = DataInputStream(peer.getInputStream())
            assertEquals(0x0502, input.readUnsignedShort())
            assertEquals(0x0100, input.readUnsignedShort())
            assertEquals(0x0500, input.readUnsignedShort())
            input.readUnsignedByte()
            val size = when (input.readUnsignedByte()) { 1 -> 4; 4 -> 16; else -> error("SOCKS_ATYP") }
            input.readFully(ByteArray(size + 2))
            return peer
        } catch (error: Throwable) { peer.close(); throw error }
    }

    private fun echo(peer: Socket) {
        val bytes = byteArrayOf(78, 73, 79, 6, 0, 1)
        peer.getOutputStream().write(bytes)
        val reply = ByteArray(bytes.size)
        DataInputStream(peer.getInputStream()).readFully(reply)
        assertArrayEquals(bytes, reply)
    }
}
