// Copyright (c) 2026 cheig; GPL-3.0.
package com.example.layanalyzer

import android.content.Context
import android.net.ConnectivityManager
import android.net.Network
import android.net.NetworkCapabilities
import android.net.http.X509TrustManagerExtensions
import android.os.SystemClock
import android.util.Base64
import android.util.Log
import androidx.test.core.app.ApplicationProvider
import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.platform.app.InstrumentationRegistry
import com.example.layanalyzer.capture.tls.*
import com.example.layanalyzer.model.TlsCaptureSettings
import com.example.layanalyzer.model.TlsCaptureStatus
import java.io.IOException
import java.io.DataInputStream
import java.net.InetSocketAddress
import java.net.Socket
import java.net.URL
import java.security.KeyStore
import java.security.cert.CertificateFactory
import java.util.Collections
import java.util.UUID
import java.util.concurrent.atomic.AtomicInteger
import java.util.concurrent.atomic.AtomicReference
import javax.net.ssl.TrustManagerFactory
import javax.net.ssl.X509TrustManager
import org.json.JSONObject
import org.junit.Assert.*
import org.junit.Test
import org.junit.runner.RunWith

/**
 * Real protocol peers on a controlled host, bridged through Android's production
 * coordinator/JNI/gateway/Go engine. OpenSSL emits real KeyUpdate messages; Go
 * peers prove ECH acceptance on both endpoints. No VPN/TUN is created here.
 * The only trust injection is an ephemeral fixture root in an in-memory Android
 * trust manager. The system trust store and installed proxy CA are not changed.
 */
@RunWith(AndroidJUnit4::class)
class TlsProtocolBoundaryTest {
    private val context = ApplicationProvider.getApplicationContext<Context>()
    private val arguments = InstrumentationRegistry.getArguments()

    @Test
    fun keyUpdatesOnBothProxyLegsPreserveApplicationBytes() = runBoundary("keyupdate", intercept = true)

    @Test
    fun realEchNegotiatesThroughAnOutOfScopeOuterName() = runBoundary("ech", intercept = false)

    @Test
    fun interceptingTheOuterNameRejectsEchWithoutRequestReplay() = runBoundary("ech", intercept = true)

    private fun runBoundary(kind: String, intercept: Boolean) {
        NativeTestSupport.awaitApplicationEngine()
        assertTrue("protocol boundaries require TLS ON", BuildConfig.TLS_ENABLED)
        assertFalse("protocol boundaries require the production engine", BuildConfig.TLS_PROBE_ENABLED)
        val connectivity = context.getSystemService(ConnectivityManager::class.java)
        val network = requireNotNull(connectivity.activeNetwork)
        assertFalse("stop VPN capture before these independent boundary tests",
            connectivity.getNetworkCapabilities(network)!!.hasTransport(NetworkCapabilities.TRANSPORT_VPN))
        val host = requireNotNull(arguments.getString("hostGateway"))
        val controlPort = requireNotNull(arguments.getString("boundaryControlPort")?.toIntOrNull())
        val base = "http://$host:$controlPort"
        val ca = TlsCertificateManager(context)
        ca.ensureGenerated()
        val session = request(network, "$base/session", "POST", JSONObject()
            .put("kind", kind)
            .put("proxyCaDer", Base64.encodeToString(ca.exportPublicCertificate().certificateDer, Base64.NO_WRAP)))
        val id = session.getString("id")
        require(id.matches(Regex("[a-f0-9]{32}")))
        val captureId = "tls-217-protocol-${UUID.randomUUID()}"
        val secrets = TlsSecretStore(context)
        val observer = ObservingBridge()
        val protector = UpstreamSocketProtector(
            { UpstreamSocketProtector.NetworkSnapshot(network, 1L) }, { true })
        val access = object : TlsNetworkAccess {
            override val generation = 1L
            override val upstream = protector
            override fun prepareHopSocket(socket: Socket) { }
            override fun close() { }
        }
        val verifier = fixtureVerifier(Base64.decode(session.getString("caDer"), Base64.NO_WRAP))
        val originPort = session.getInt("originPort")
        // ECH's private inner name cannot be inferred from its outer ClientHello.
        // Including only the inner name must therefore select passthrough.
        val included = if (kind == "ech" && intercept) OUTER else INNER
        val coordinator = TlsCaptureCoordinator(captureId,
            TlsCaptureSettings(enabled = true, candidatePorts = setOf(originPort), includeHosts = listOf(included)),
            network = access, certificates = { ca }, secretStore = { secrets }, bridge = observer,
            verification = TlsUpstreamVerification(verifier::verifyUpstream))
        try {
            val started = coordinator.start()
            assertTrue("production coordinator must start", started is TlsCaptureStart.Started)
            started as TlsCaptureStart.Started
            val bridgeResult = runCatching { started.gateway.withNioConnection(host, originPort) { gateway ->
                network.socketFactory.createSocket().use { clientPeer ->
                    clientPeer.connect(InetSocketAddress(host, session.getInt("clientPort")), 5_000)
                    bridge(clientPeer, gateway)
                }
            } }
            val result = request(network, "$base/result/$id")
            val deadline = SystemClock.elapsedRealtime() + 5_000
            do {
                coordinator.pump()
                if (observer.events.any { it.getString("phase") in listOf("CLOSED", "FAILED") }) break
                Thread.sleep(20)
            } while (SystemClock.elapsedRealtime() < deadline)
            val stopped = coordinator.stop()
            assertEquals(TlsCaptureStatus.STOPPED, stopped.status)
            val events = observer.events.toList()
            val phases = events.map { it.getString("phase") }
            Log.i(TAG, "OBSERVED kind=$kind intercept=$intercept phases=$phases counts=${stopped.connections} peers=$result")
            bridgeResult.getOrThrow()
            assertEquals("one dial, no reconnect or replay", 1, observer.prepared.get())
            assertEquals("one connection", 1L, stopped.connections.accepted)
            assertEquals("one terminal event", 1, phases.count { it == "CLOSED" || it == "FAILED" })
            assertTrue("secrets must finish persisting", stopped.secretsComplete)
            val client = result.getJSONObject("client")
            val origin = result.getJSONObject("origin")
            if (kind == "keyupdate") {
                for (peer in listOf(client, origin)) {
                    assertTrue("peer must verify all application bytes: $result", peer.getBoolean("ok"))
                    assertEquals(0x0304, peer.getInt("version"))
                    assertEquals(65_536, peer.getInt("bytes"))
                    val sent = peer.getJSONArray("updatesSent")
                    val received = peer.getJSONArray("updatesReceived")
                    assertTrue("peer must send request_update", (0 until sent.length()).any { sent.getInt(it) == 1 })
                    assertTrue("the proxy must acknowledge KeyUpdate", (0 until received.length()).any { received.getInt(it) == 0 })
                }
                assertEquals("CLOSED", phases.last())
                assertTrue(phases.contains("RELAYING"))
                assertFalse(phases.contains("PASSTHROUGH"))
                assertEquals(1L, stopped.connections.proxied)
                assertEquals(0L, stopped.connections.failed)
                assertEquals(65_536L, stopped.traffic.bytesToUpstream)
                assertEquals(65_536L, stopped.traffic.bytesToDownstream)
                assertTrue("real downstream secrets must exist", observer.offers.get() >= 4)
                assertEquals(observer.offers.get().toLong(), stopped.secrets!!.persisted)
            } else if (!intercept) {
                for (peer in listOf(client, origin)) {
                    assertTrue("ECH bytes must round-trip: $result", peer.getBoolean("ok"))
                    assertTrue("real endpoint ECH acceptance required", peer.getBoolean("echAccepted"))
                    assertEquals(INNER, peer.getString("serverName"))
                    assertEquals(0x0304, peer.getInt("version"))
                    assertEquals(34_816, peer.getInt("bytes"))
                }
                assertEquals(listOf("ACCEPTED", "SNIFFING", "PASSTHROUGH", "CLOSED"), phases)
                assertEquals(1L, stopped.connections.passthrough)
                assertEquals(0L, stopped.connections.proxied)
                assertEquals(0, observer.offers.get())
                assertEquals(0, observer.verified.get())
                assertTrue("the engine sees only ECH's outer name", events.any { it.optString("sni") == OUTER })
                assertFalse("inner name must remain hidden", events.any { it.optString("sni") == INNER })
            } else {
                assertFalse(client.getBoolean("ok"))
                assertTrue("must fail specifically as ECH rejection: $result", client.getBoolean("echRejected"))
                assertFalse(client.getBoolean("echAccepted"))
                assertFalse(origin.getBoolean("echAccepted"))
                assertEquals(0, origin.getInt("bytes"))
                assertEquals("FAILED", phases.last())
                assertTrue(phases.contains("DOWNSTREAM_HANDSHAKE"))
                assertFalse(phases.contains("PASSTHROUGH"))
                // A TLS 1.3 client authenticates the outer handshake before it
                // reports ECH rejection. The server may finish its handshake
                // and enter RELAYING before reading that client's fatal alert.
                // Assert the final failure and zero origin application bytes.
                assertTrue(phases.contains("RELAYING"))
                assertEquals(1L, stopped.connections.failed)
                assertEquals("proxied counts entry into relay, not application success", 1L, stopped.connections.proxied)
                assertEquals(0L, stopped.connections.closed)
                assertEquals(0L, stopped.connections.passthrough)
                assertEquals(0L, stopped.traffic.bytesToUpstream)
            }
            if (intercept) assertEquals("real platform verification with test root", 1, observer.verified.get())
            assertThrows("stop must close the gateway", IOException::class.java) {
                Socket().use { it.connect(InetSocketAddress("127.0.0.1", started.port), 1_000) }
            }
            Log.i(TAG, "PASS kind=$kind intercept=$intercept phases=$phases " +
                "dialCount=${observer.prepared.get()} secretOffers=${observer.offers.get()} " +
                "persisted=${stopped.secrets?.persisted ?: 0} peers=$result")
        } finally {
            try {
                coordinator.close()
                secrets.purgeCapture(captureId)
            } finally {
                request(network, "$base/session/$id", "DELETE")
            }
        }
    }

    private fun fixtureVerifier(root: ByteArray): AndroidUpstreamTrustVerifier {
        val store = KeyStore.getInstance(KeyStore.getDefaultType()).apply {
            load(null)
            setCertificateEntry("fixture", CertificateFactory.getInstance("X.509").generateCertificate(root.inputStream()))
        }
        val factory = TrustManagerFactory.getInstance("X509").apply { init(store) }
        val manager = factory.trustManagers.filterIsInstance<X509TrustManager>().single()
        val extensions = X509TrustManagerExtensions(manager)
        return AndroidUpstreamTrustVerifier { chain, authType, host ->
            extensions.checkServerTrusted(chain, authType, host)
        }
    }

    private fun request(network: Network, url: String, method: String = "GET", body: JSONObject? = null): JSONObject {
        // Test control transport contains public certificates and counters only.
        // Use a bounded raw socket, as existing device fixtures do, without
        // changing the application's cleartext HTTP or network security policy.
        val target = URL(url)
        return network.socketFactory.createSocket().use { socket ->
            socket.connect(InetSocketAddress(target.host, target.port), 5_000)
            socket.soTimeout = 35_000
            val bytes = body?.toString()?.toByteArray(Charsets.UTF_8) ?: ByteArray(0)
            val header = "$method ${target.path} HTTP/1.0\r\nHost: fixture\r\n" +
                "Content-Type: application/json\r\nContent-Length: ${bytes.size}\r\n\r\n"
            socket.outputStream.write(header.toByteArray(Charsets.US_ASCII))
            socket.outputStream.write(bytes)
            socket.outputStream.flush()
            val input = DataInputStream(socket.inputStream.buffered())
            var headerBytes = 0
            fun line(): String {
                val text = StringBuilder()
                while (true) {
                    val next = input.readUnsignedByte()
                    assertTrue("fixture header budget", ++headerBytes <= 4_096)
                    if (next == 10) return text.toString().removeSuffix("\r")
                    text.append(next.toChar())
                }
            }
            assertEquals("controlled fixture must answer", "200", line().split(' ')[1])
            var length = -1
            while (true) {
                val entry = line()
                if (entry.isEmpty()) break
                if (entry.startsWith("Content-Length:", ignoreCase = true)) length = entry.substringAfter(':').trim().toInt()
            }
            assertTrue("fixture response budget", length in 0..16_384)
            val response = ByteArray(length)
            input.readFully(response)
            JSONObject(response.toString(Charsets.UTF_8))
        }
    }

    private fun bridge(client: Socket, gateway: Socket) {
        client.soTimeout = 30_000
        gateway.soTimeout = 30_000
        val error = AtomicReference<Throwable?>()
        fun copy(source: Socket, target: Socket) {
            try {
                source.inputStream.copyTo(target.outputStream, 32 * 1024)
                target.shutdownOutput()
            } catch (failure: Throwable) {
                error.compareAndSet(null, failure)
            }
        }
        val reverse = Thread({ copy(gateway, client) }, "tls-217-peer-return").apply { start() }
        try {
            copy(client, gateway)
            reverse.join(35_000)
            assertFalse("bounded peer bridge shutdown", reverse.isAlive)
            error.get()?.let { throw AssertionError("protocol peer bridge failed", it) }
        } finally {
            client.close()
            gateway.close()
            reverse.join(2_000)
        }
    }

    private class ObservingBridge : TlsEngineBridge {
        private val real = TlsProxyBridge()
        val prepared = AtomicInteger()
        val verified = AtomicInteger()
        val offers = AtomicInteger()
        val events = Collections.synchronizedList(mutableListOf<JSONObject>())
        override fun capabilities() = real.capabilities()
        override fun start(configJson: String, certificateDer: ByteArray, privateKeyPkcs8: ByteArray,
            callbacks: TlsPlatformCallbacks): String = real.start(configJson, certificateDer, privateKeyPkcs8,
            object : TlsPlatformCallbacks by callbacks {
                override fun prepareSocket(fd: Int, networkGeneration: Long): String =
                    callbacks.prepareSocket(fd, networkGeneration).also {
                        if (JSONObject(it).getBoolean("success")) prepared.incrementAndGet()
                    }
                override fun verifyUpstream(chainDer: Array<ByteArray>, identity: String, authType: String,
                    tlsVersion: String): String {
                    verified.incrementAndGet()
                    return callbacks.verifyUpstream(chainDer, identity, authType, tlsVersion)
                }
                override fun offerSecret(captureId: String, connectionId: String, line: ByteArray): Boolean {
                    offers.incrementAndGet()
                    return callbacks.offerSecret(captureId, connectionId, line)
                }
            })
        override fun stop(handle: Long, timeoutMillis: Int) = real.stop(handle, timeoutMillis)
        override fun stats(handle: Long) = real.stats(handle)
        override fun gatewayToken(handle: Long) = real.gatewayToken(handle)
        override fun poll(handle: Long, maxEvents: Int): String = real.poll(handle, maxEvents).also {
            val rows = JSONObject(it).optJSONArray("events")
            if (rows != null) for (index in 0 until rows.length()) events += rows.getJSONObject(index)
        }
    }

    private companion object {
        const val TAG = "TLS-217-Protocol"
        const val INNER = "inner.boundary.test"
        const val OUTER = "outer.boundary.test"
    }
}
