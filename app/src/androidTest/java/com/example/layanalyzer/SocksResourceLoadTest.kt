// Copyright (c) 2026 cheig; GPL-3.0.
package com.example.layanalyzer

import android.content.Context
import android.content.Intent
import android.net.ConnectivityManager
import android.net.Network
import android.net.NetworkCapabilities
import android.net.VpnService
import android.net.http.X509TrustManagerExtensions
import android.os.SystemClock
import androidx.core.content.ContextCompat
import androidx.test.core.app.ApplicationProvider
import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.platform.app.InstrumentationRegistry
import com.example.layanalyzer.capture.DirectSocks5Server
import com.example.layanalyzer.capture.LiveCaptureStore
import com.example.layanalyzer.capture.LiveCaptureVpnService
import com.example.layanalyzer.capture.tls.AndroidUpstreamTrustVerifier
import com.example.layanalyzer.capture.tls.TlsGatewayChannel
import com.example.layanalyzer.capture.tls.TlsPlatformCallbacks
import com.example.layanalyzer.capture.tls.TlsProxyBridge
import com.example.layanalyzer.capture.tls.TlsRoutingPolicy
import com.example.layanalyzer.capture.tls.UpstreamChainVerifier
import com.example.layanalyzer.capture.tls.UpstreamSocketProtector
import com.example.layanalyzer.model.TlsCaptureSettings
import org.json.JSONArray
import org.json.JSONObject
import org.junit.Assume.assumeTrue
import org.junit.Test
import org.junit.runner.RunWith
import java.io.Closeable
import java.io.DataInputStream
import java.io.File
import java.net.DatagramPacket
import java.net.DatagramSocket
import java.net.InetAddress
import java.net.InetSocketAddress
import java.net.Socket
import java.security.KeyStore
import java.security.MessageDigest
import java.security.cert.CertificateFactory
import java.util.UUID
import java.util.concurrent.atomic.AtomicInteger
import javax.net.ssl.SSLContext
import javax.net.ssl.SSLSocket
import javax.net.ssl.TrustManagerFactory
import javax.net.ssl.X509TrustManager

/** Opt-in P0 fixture; no production limits changed. Clients use this test thread only.
 * Real Go gateway/TLS are measured directly using TLS-204's in-memory fixture trust.
 * HEV measurements use the real VPN service with TLS disabled, in the same process.
 */
@RunWith(AndroidJUnit4::class)
class SocksResourceLoadTest {
    private val context = ApplicationProvider.getApplicationContext<Context>()
    private val args = InstrumentationRegistry.getArguments()
    private val connectivity = context.getSystemService(ConnectivityManager::class.java)
    private val bridge = TlsProxyBridge()
    private lateinit var directory: File
    private lateinit var host: String
    private lateinit var root: ByteArray
    private var tcpPort = 0
    private var udpPort = 0
    private var tlsPort = 0
    private val name = "upstream.fixture.test"

    @Test
    fun measureControlledPaths() {
        val runId = args.getString("loadRunId")
        assumeTrue("Opt-in controlled resource fixture", runId != null)
        require(requireNotNull(runId).matches(Regex("[a-f0-9]{32}")))
        check(BuildConfig.TLS_ENABLED && !BuildConfig.TLS_PROBE_ENABLED)
        check(VpnService.prepare(context) == null) { "VPN_CONSENT_REQUIRED" }
        check(!LiveCaptureStore.state.value.isCapturing)
        NativeTestSupport.awaitApplicationEngine()
        directory = File(context.filesDir, "socks-nio-load/$runId").apply { mkdirs() }
        host = requireNotNull(args.getString("hostGateway"))
        tcpPort = requireNotNull(args.getString("hostTcpPort")).toInt()
        udpPort = requireNotNull(args.getString("hostUdpPort")).toInt()
        tlsPort = requireNotNull(args.getString("hostTlsPort")).toInt()
        root = File(context.filesDir, "socks-nio-load/root-$runId.der").readBytes()
        val hash = MessageDigest.getInstance("SHA-256").digest(root).joinToString("") { "%02x".format(it) }
        check(hash == args.getString("rootSha256")) { "FIXTURE_ROOT_MISMATCH" }
        // Warm Android TLS and validate the actual fixture certificate before sampling.
        val physical = physicalNetwork()
        val originContext = sslContext(root)
        Socket().use { raw ->
            physical.bindSocket(raw)
            raw.connect(InetSocketAddress(host, tlsPort), 5000)
            (originContext.socketFactory.createSocket(raw, name, tlsPort, true) as SSLSocket).use {
                configureTls(it)
                it.startHandshake()
                echo(it)
            }
        }
        val modes = listOf("direct_tcp", "direct_udp", "tls_candidate", "tls_proxied", "vpn_tcp", "vpn_udp")
        for (mode in modes) measure(mode)
    }

    private fun measure(mode: String) {
        val vpnMode = mode.startsWith("vpn_")
        val tlsMode = mode.startsWith("tls_")
        val udpMode = mode.endsWith("udp")
        val candidate = mode == "tls_candidate"
        val clients = mutableListOf<Closeable>()
        val events = JSONArray()
        val outcome = JSONObject().put("mode", mode).put("clientThreads", 0)
            .put("clientFdPerSession", if (mode == "direct_udp") 2 else 1)
            .put("candidateShortWindow", candidate).put("failures", 0)
        val physical = physicalNetwork()
        var socks: DirectSocks5Server? = null
        var channel: TlsGatewayChannel? = null
        var handle = 0L
        var port = 0
        var ownsVpn = false
        var sampler: ProcessResourceSampler? = null
        val verifies = AtomicInteger()
        val secrets = AtomicInteger()
        var clientTls: SSLContext? = null
        fun pollGo() {
            if (handle == 0L) return
            val polled = JSONObject(bridge.poll(handle, 128))
            check(polled.getBoolean("success")) { "GO_POLL_FAILED" }
            val list = polled.getJSONArray("events")
            for (i in 0 until list.length()) {
                val e = list.getJSONObject(i)
                // Never write addresses, SNI, connection IDs, or secret records.
                events.put(JSONObject().put("phase", e.optString("phase"))
                    .put("reason", e.optString("decisionReason")).put("errorCode", e.optString("errorCode")))
            }
        }
        try {
            if (tlsMode) {
                val protector = UpstreamSocketProtector(
                    { UpstreamSocketProtector.NetworkSnapshot(physical, 1L) }, { true })
                val extensions = X509TrustManagerExtensions(trustManager(root))
                val verifier = AndroidUpstreamTrustVerifier(UpstreamChainVerifier { chain, auth, identity ->
                    extensions.checkServerTrusted(chain, auth, identity)
                })
                val callbacks = object : TlsPlatformCallbacks {
                    override fun prepareSocket(fd: Int, networkGeneration: Long) = protector.prepareSocket(fd, networkGeneration)
                    override fun resolveHost(host: String, networkGeneration: Long) = protector.resolveHost(host, networkGeneration)
                    override fun verifyUpstream(chainDer: Array<ByteArray>, identity: String, authType: String, tlsVersion: String): String {
                        verifies.incrementAndGet()
                        return verifier.verifyUpstream(chainDer, identity, authType, tlsVersion)
                    }
                    override fun offerSecret(captureId: String, connectionId: String, line: ByteArray): Boolean {
                        line.fill(0)
                        secrets.incrementAndGet()
                        return true // Test sink acknowledges disposal; no persistence claim.
                    }
                }
                val policy = TlsRoutingPolicy.freeze(TlsCaptureSettings(enabled = true,
                    candidatePorts = setOf(tlsPort), includeHosts = listOf(name)))
                val material = NativeEngine.generateTlsCaMaterial()
                try {
                    clientTls = sslContext(material[0])
                    val config = JSONObject().put("schemaVersion", 1).put("captureId", "nio-003-$mode")
                        .put("networkGeneration", 1).put("settings", JSONObject(policy.encode()))
                    val start = JSONObject(bridge.start(config.toString(), material[0], material[1], callbacks))
                    check(start.getBoolean("success")) { "GO_START_FAILED" }
                    handle = start.getLong("engineHandle")
                    channel = TlsGatewayChannel(start.getInt("port"), bridge.gatewayToken(handle),
                        "nio-003-$mode", 1L, policy, prepareHopSocket = { })
                } finally { material.forEach { it.fill(0) } }
            }
            if (vpnMode) {
                LiveCaptureStore.clearError()
                ownsVpn = true
                ContextCompat.startForegroundService(context, Intent(context, LiveCaptureVpnService::class.java).apply {
                    putExtra(LiveCaptureVpnService.EXTRA_EXCLUDE_SELF, false)
                    putExtra(LiveCaptureVpnService.EXTRA_CAPTURE_IPV6, false)
                    putStringArrayListExtra(LiveCaptureVpnService.EXTRA_ALLOWED_APPLICATIONS, arrayListOf(context.packageName))
                })
                waitUntil { LiveCaptureStore.state.value.isCapturing && activeVpn() != null }
            } else {
                socks = DirectSocks5Server(prepareTcp = { physical.bindSocket(it) },
                    prepareUdp = { physical.bindSocket(it) }, resolveHost = { physical.getAllByName(it) }, tlsGateway = channel)
                port = socks.start()
            }
            val id = UUID.randomUUID().toString().replace("-", "")
            sampler = ProcessResourceSampler(File(directory, "$mode.jsonl"), id,
                sessions = { if (vpnMode) LiveCaptureVpnService.socksResourceSnapshot() else socks?.sessionStats() })
            fun sample(phase: String) {
                sampler.sample(phase)
                pollGo()
            }
            // Same 5-second cadence and three snapshots for before/held/after phases.
            fun phase(label: String) { repeat(3) { SystemClock.sleep(5000); sample(label) } }
            phase("before")
            val targets = if (candidate) listOf(8) else listOf(8, 16)
            var established = 0
            val rampStart = SystemClock.elapsedRealtime()
            for (target in targets) {
                repeat(target - established) { index ->
                    if (udpMode) {
                        val relay = if (vpnMode) null else openSocks(requireNotNull(socks), port, 3, "0.0.0.0", 0).also { clients += it.first }.second
                        val client = DatagramSocket().also { clients += it }
                        if (vpnMode) requireNotNull(activeVpn()).bindSocket(client)
                        client.soTimeout = 3000
                        val payload = byteArrayOf(0x41, index.toByte())
                        val wire = if (relay == null) payload else byteArrayOf(0, 0, 0, 1) +
                            InetAddress.getByName(host).address + byteArrayOf((udpPort ushr 8).toByte(), udpPort.toByte()) + payload
                        client.send(DatagramPacket(wire, wire.size, relay ?: InetSocketAddress(host, udpPort)))
                        val reply = DatagramPacket(ByteArray(256), 256)
                        client.receive(reply)
                        check(reply.data.copyOfRange(reply.length - 2, reply.length).contentEquals(payload)) { "UDP_ECHO_MISMATCH" }
                    } else {
                        val raw = if (vpnMode) Socket().also {
                            clients += it
                            requireNotNull(activeVpn()).bindSocket(it)
                            it.connect(InetSocketAddress(host, tcpPort), 5000)
                        } else openSocks(requireNotNull(socks), port, 1, host, if (tlsMode) tlsPort else tcpPort).first.also { clients += it }
                        if (mode == "tls_proxied") {
                            val secure = requireNotNull(clientTls).socketFactory.createSocket(raw, name, tlsPort, true) as SSLSocket
                            clients += secure
                            configureTls(secure)
                            secure.startHandshake()
                            echo(secure)
                        } else if (!candidate) echo(raw)
                        // Candidate intentionally sends no ClientHello. Real Go must still be SNIFFING.
                    }
                    established++
                }
                waitUntil {
                    val stats = if (vpnMode) LiveCaptureVpnService.socksResourceSnapshot() else socks?.sessionStats()
                    (if (udpMode) stats?.udp?.current else stats?.tcp?.current) == target
                }
                if (candidate) {
                    check(SystemClock.elapsedRealtime() - rampStart < 2500) { "CANDIDATE_PROBE_WINDOW_EXPIRED" }
                    sample("held_$target") // Whole probe deadline is 3 s: this is a boundary, not a steady-state point.
                    check(SystemClock.elapsedRealtime() - rampStart < 2500) { "CANDIDATE_SAMPLE_WINDOW_EXPIRED" }
                    check(events.length() > 0)
                    check((0 until events.length()).count { events.getJSONObject(it).getString("phase") == "SNIFFING" } == target)
                    check((0 until events.length()).none { events.getJSONObject(it).getString("phase") in listOf("PASSTHROUGH", "RELAYING", "FAILED") })
                } else phase("held_$target")
                outcome.put("established", established)
            }
            if (tlsMode) {
                val goStats = JSONObject(bridge.stats(handle))
                outcome.put("goBeforeStop", goStats.getJSONObject("events"))
                    .put("goBudgetBeforeStop", goStats.getJSONObject("budget"))
                if (!candidate) {
                    check(verifies.get() == established) { "UPSTREAM_VERIFY_COUNT" }
                    check((0 until events.length()).count { events.getJSONObject(it).getString("phase") == "RELAYING" } == established) { "NOT_ALL_CONNECTIONS_PROXIED" }
                    check(secrets.get() > 0) { "NO_REAL_TLS_SECRETS" }
                }
            }
            val stopStarted = SystemClock.elapsedRealtime()
            clients.asReversed().forEach { runCatching { it.close() } }
            clients.clear()
            if (vpnMode) { stopVpn(); ownsVpn = false } else socks?.close()
            channel?.close()
            if (handle != 0L) {
                pollGo()
                val goStats = JSONObject(bridge.stats(handle))
                outcome.put("goAtStop", goStats.getJSONObject("events"))
                    .put("goBudgetAtStop", goStats.getJSONObject("budget"))
                stopGo(handle)
                handle = 0L
            }
            outcome.put("stopMillis", SystemClock.elapsedRealtime() - stopStarted)
            phase("after_stop")
            val stats = requireNotNull(if (vpnMode) LiveCaptureVpnService.socksResourceSnapshot() else socks?.sessionStats())
            check(stats.tcp.current == 0 && stats.udp.current == 0 && stats.handshakes.current == 0) { "SESSIONS_NOT_RELEASED" }
            check(stats.rejectedTcp == 0L && stats.rejectedUdp == 0L && stats.rejectedHandshakes == 0L) { "CAPACITY_REJECTION" }
            outcome.put("upstreamVerifications", verifies.get()).put("secretOffersDisposed", secrets.get())
                .put("goPhases", events).put("complete", true)
        } catch (error: Throwable) {
            outcome.put("complete", false).put("failures", 1).put("errorType", error.javaClass.simpleName)
            if (handle != 0L) runCatching {
                pollGo()
                outcome.put("goOnFailure", JSONObject(bridge.stats(handle)).getJSONObject("events"))
                    .put("goPhases", events)
            }
            throw error
        } finally {
            clients.asReversed().forEach { runCatching { it.close() } }
            val cleanupErrors = JSONArray()
            fun cleanup(action: () -> Unit) { runCatching(action).onFailure { cleanupErrors.put(it.javaClass.simpleName) } }
            if (ownsVpn) cleanup { stopVpn() }
            cleanup { socks?.close() }
            cleanup { channel?.close() }
            if (handle != 0L) cleanup { stopGo(handle) }
            cleanup { sampler?.close() }
            if (cleanupErrors.length() > 0) outcome.put("complete", false).put("cleanupErrors", cleanupErrors)
            File(directory, "$mode-result.json").writeText(outcome.toString(2))
            check(cleanupErrors.length() == 0) { "LOAD_CLEANUP_FAILED" }
        }
    }

    private fun openSocks(server: DirectSocks5Server, port: Int, command: Int, target: String, targetPort: Int): Pair<Socket, InetSocketAddress> {
        val socket = Socket("127.0.0.1", port)
        try {
            socket.soTimeout = 15000
            val out = socket.getOutputStream()
            val input = DataInputStream(socket.getInputStream())
            out.write(byteArrayOf(5, 1, 2)); check(input.readUnsignedShort() == 0x0502)
            val user = server.credentials.username.toByteArray(Charsets.US_ASCII)
            val password = server.credentials.password.toByteArray(Charsets.US_ASCII)
            try { out.write(byteArrayOf(1, user.size.toByte()) + user + byteArrayOf(password.size.toByte()) + password) }
            finally { user.fill(0); password.fill(0) }
            check(input.readUnsignedShort() == 0x0100)
            out.write(byteArrayOf(5, command.toByte(), 0, 1) + InetAddress.getByName(target).address +
                byteArrayOf((targetPort ushr 8).toByte(), targetPort.toByte()))
            check(input.readUnsignedShort() == 0x0500) { "SOCKS_REQUEST_FAILED" }
            input.readUnsignedByte()
            val address = ByteArray(when (input.readUnsignedByte()) { 1 -> 4; 4 -> 16; else -> error("SOCKS_ADDRESS") })
            input.readFully(address)
            return socket to InetSocketAddress(InetAddress.getByAddress(address), input.readUnsignedShort())
        } catch (error: Throwable) { socket.close(); throw error }
    }

    private fun echo(socket: Socket) {
        socket.soTimeout = 10000
        val payload = byteArrayOf(0x4e, 0x49, 0x4f, 3)
        socket.getOutputStream().write(payload)
        val response = ByteArray(payload.size)
        DataInputStream(socket.getInputStream()).readFully(response)
        check(response.contentEquals(payload)) { "TCP_ECHO_MISMATCH" }
    }
    private fun configureTls(socket: SSLSocket) {
        socket.soTimeout = 15000
        socket.enabledProtocols = arrayOf("TLSv1.3")
        socket.sslParameters = socket.sslParameters.apply { endpointIdentificationAlgorithm = "HTTPS" }
    }
    private fun trustManager(certificate: ByteArray): X509TrustManager {
        val store = KeyStore.getInstance(KeyStore.getDefaultType()).apply {
            load(null, null)
            setCertificateEntry("fixture", CertificateFactory.getInstance("X.509").generateCertificate(certificate.inputStream()))
        }
        return TrustManagerFactory.getInstance("X509").apply { init(store) }.trustManagers.filterIsInstance<X509TrustManager>().single()
    }
    private fun sslContext(certificate: ByteArray) = SSLContext.getInstance("TLS").apply { init(null, arrayOf(trustManager(certificate)), null) }
    private fun physicalNetwork(): Network = connectivity.allNetworks.first {
        // This fixture explicitly targets a controlled LAN, not a cellular interface.
        connectivity.getNetworkCapabilities(it)?.let { c ->
            !c.hasTransport(NetworkCapabilities.TRANSPORT_VPN) && c.hasTransport(NetworkCapabilities.TRANSPORT_WIFI)
        } == true
    }
    private fun activeVpn() = connectivity.activeNetwork?.takeIf { connectivity.getNetworkCapabilities(it)?.hasTransport(NetworkCapabilities.TRANSPORT_VPN) == true }
    private fun stopVpn() {
        context.startService(Intent(context, LiveCaptureVpnService::class.java).setAction(LiveCaptureVpnService.ACTION_STOP))
        waitUntil { !LiveCaptureStore.state.value.isCapturing && activeVpn() == null }
    }
    private fun stopGo(handle: Long) = waitUntil { JSONObject(bridge.stop(handle, 5000)).getBoolean("success") }
    private fun waitUntil(condition: () -> Boolean) {
        val until = SystemClock.elapsedRealtime() + 30000
        while (!condition()) { check(SystemClock.elapsedRealtime() < until) { "LIFECYCLE_TIMEOUT" }; SystemClock.sleep(50) }
    }
}
