package com.example.layanalyzer

import android.content.Context
import android.net.ConnectivityManager
import android.net.Network
import android.net.NetworkCapabilities
import android.os.SystemClock
import androidx.test.core.app.ApplicationProvider
import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.platform.app.InstrumentationRegistry
import com.example.layanalyzer.capture.DirectSocks5Server
import com.example.layanalyzer.capture.SocksCredentials
import com.example.layanalyzer.capture.tls.AndroidUpstreamTrustVerifier
import com.example.layanalyzer.capture.tls.TlsConnectionStore
import com.example.layanalyzer.capture.tls.TlsGatewayChannel
import com.example.layanalyzer.capture.tls.TlsPlatformCallbacks
import com.example.layanalyzer.capture.tls.TlsProxyBridge
import com.example.layanalyzer.capture.tls.TlsRoutingPolicy
import com.example.layanalyzer.capture.tls.UpstreamSocketProtector
import com.example.layanalyzer.model.TlsCaptureSettings
import java.io.DataInputStream
import java.io.DataOutputStream
import java.io.IOException
import java.net.InetAddress
import java.net.Socket
import java.nio.charset.StandardCharsets
import java.util.concurrent.atomic.AtomicInteger
import org.json.JSONObject
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertThrows
import org.junit.Assert.assertTrue
import org.junit.Test
import org.junit.runner.RunWith

/**
 * TLS-212 on a device (arm64): the real Go engine publishes the shared capacity
 * budget, the bounded event queue's counters and the per-connection statistics
 * over the production C ABI, and the production reader half — [TlsConnectionStore] —
 * parses exactly those numbers back.
 *
 * The card's verification code is `G（race）; J=TlsConnectionStoreTest`: it has no
 * `D` item, so this class is the device gate that closes that gap. It drives one
 * **passthrough** connection (the controlled plain-HTTP fixture the live-capture
 * tests already use; `hostGateway` / `hostHttpPort`) through the production SOCKS
 * server and the real `LAT1` gateway, so the `Budget`, the `Queue` and the `Stats`
 * aggregation are all exercised on hardware without needing a decrypted payload
 * or a VPN. No Assume: a missing fixture argument or an unreachable device is an
 * unfulfilled gate, not a pass.
 *
 * What this deliberately does **not** claim: no >64 concurrent-connection load
 * (the first capacity gate is the SOCKS layer's own `Semaphore(64)`, which refuses
 * before the Go budget can, so a device load test would mostly measure that outer
 * gate and is left out on purpose — recorded in the evidence); no VPN, hence no
 * `protect`/`bind` semantics (still TLS-203/TLS-218); and no decryption.
 */
@RunWith(AndroidJUnit4::class)
class TlsSharedCapacityStatsTest {
    private val context = ApplicationProvider.getApplicationContext<Context>()
    private val connectivity = context.getSystemService(ConnectivityManager::class.java)
    private val arguments = InstrumentationRegistry.getArguments()
    private val bridge = TlsProxyBridge()

    @Test
    fun theEnginePublishesItsBudgetEventAndTrafficCountersAndTheStoreMatchesThem() {
        if (!BuildConfig.TLS_ENABLED) {
            // Without the build switch there is no engine to count anything; the
            // only honest assertion is that the boundary refuses to pretend.
            val refusal = assertThrows(IllegalStateException::class.java) { bridge.gatewayToken(1) }
            assertEquals("UNSUPPORTED", refusal.message)
            return
        }

        val host = requireNotNull(arguments.getString("hostGateway")) {
            "Required fixture argument: hostGateway — a host reachable from the device " +
                "(10.0.2.2 on an emulator, a controlled LAN address on a real device)"
        }
        val port = (arguments.getString("hostHttpPort") ?: DEFAULT_HTTP_PORT.toString()).toInt()
        val generation = 1L
        val network = requireNotNull(physicalNetwork()) {
            "The device has no physical network; the gateway dials the captured network only"
        }
        val protector = UpstreamSocketProtector(
            { UpstreamSocketProtector.NetworkSnapshot(network, generation) },
            // No VPN is active in this test, so there is nothing to exclude; the
            // upstream bind below is the real one.
            { true }
        )
        val secretOffers = AtomicInteger()
        val callbacks = object : TlsPlatformCallbacks {
            override fun prepareSocket(fd: Int, networkGeneration: Long): String =
                protector.prepareSocket(fd, networkGeneration)

            override fun resolveHost(host: String, networkGeneration: Long): String =
                protector.resolveHost(host, networkGeneration)

            // The production verifier, not a permissive stand-in: a passthrough
            // connection never calls it.
            override fun verifyUpstream(
                chainDer: Array<ByteArray>,
                identity: String,
                authType: String,
                tlsVersion: String
            ): String = AndroidUpstreamTrustVerifier()
                .verifyUpstream(chainDer, identity, authType, tlsVersion)

            override fun offerSecret(captureId: String, connectionId: String, line: ByteArray): Boolean {
                line.fill(0)
                secretOffers.incrementAndGet()
                return false
            }
        }

        val policy = TlsRoutingPolicy.freeze(
            TlsCaptureSettings(enabled = true, candidatePorts = setOf(port))
        )
        val config = JSONObject()
            .put("schemaVersion", 1)
            .put("captureId", CAPTURE_ID)
            .put("networkGeneration", generation)
            .put("settings", JSONObject(policy.encode()))
            .toString()

        val material = NativeEngine.generateTlsCaMaterial()
        assertEquals(2, material.size)
        val certificate = material[0]
        val privateKey = material[1]
        var handle = 0L
        try {
            val started = JSONObject(bridge.start(config, certificate, privateKey, callbacks))
            assertTrue("the engine must start for an enabled policy: $started", started.getBoolean("success"))
            handle = started.getLong("engineHandle")
            val gatewayPort = started.getInt("port")
            val token = bridge.gatewayToken(handle)

            val channel = TlsGatewayChannel(
                gatewayPort = gatewayPort,
                token = token,
                captureId = CAPTURE_ID,
                networkGeneration = generation,
                policy = policy,
                prepareHopSocket = { }
            )
            val pollResponses = mutableListOf<String>()
            val phases = mutableListOf<String>()
            try {
                val response = throughSocks(channel, handle, network, host, port, pollResponses, phases)
                assertTrue("the origin must answer through the gateway: $response", response.startsWith("HTTP/1."))
                assertTrue("a 200 from the fixture origin: $response", response.contains("200"))
                assertEquals("no connection may be intercepted here", 0, secretOffers.get())
                assertEquals("exactly one terminal state: $phases", "CLOSED", phases.last())
            } finally {
                channel.close()
            }

            // ---- the engine's own budget surface (TLS-212 §15.3) ----------------
            val statsJson = bridge.stats(handle)
            val stats = JSONObject(statsJson)
            val budget = stats.getJSONObject("budget")
            assertEquals("the shared connection ceiling is C10's 64", 64, budget.getInt("connectionLimit"))
            assertEquals("the handshake ceiling is C10's 8", 8, budget.getInt("handshakeLimit"))
            assertEquals(
                "every exit path released its connection slot",
                0, budget.getInt("connections")
            )
            assertEquals("and its handshake slot", 0, budget.getInt("handshakes"))
            val peak = budget.getInt("peakConnections")
            assertTrue("the connection was counted while it ran: peak=$peak", peak in 1..64)
            assertEquals(
                "one connection through one entry point is never refused",
                0L, budget.getLong("refusedConnections")
            )

            // ---- the event-path counters (TLS-212 §10.2) ------------------------
            val events = stats.getJSONObject("events")
            assertEquals("one connection was accepted", 1L, events.getLong("connectionsAccepted"))
            assertEquals("it was passed through", 1L, events.getLong("connectionsPassthrough"))
            assertEquals("nothing was proxied", 0L, events.getLong("connectionsProxied"))
            assertEquals("nothing failed", 0L, events.getLong("connectionsFailed"))
            assertEquals("no secret was produced", 0L, events.getLong("secretRecordsAccepted"))
            assertEquals("no secret was lost", 0L, events.getLong("secretsIncomplete"))
            assertTrue("the relay carried the request upstream", events.getLong("bytesToUpstream") > 0L)
            assertTrue("and the answer back", events.getLong("bytesToDownstream") > 0L)
            assertTrue("events were published: ${events.getLong("eventsPublished")}", events.getLong("eventsPublished") >= 1L)
            assertEquals("nothing was dropped under no pressure", 0L, events.getLong("eventsDropped"))
            assertEquals("the one terminal state was not suppressed", 0L, events.getLong("terminalsSuppressed"))
            assertTrue("the terminal summary is retained", events.getInt("terminalsRetained") >= 1)

            // ---- the poll stream: monotonic sequence, one terminal --------------
            val sequences = mutableListOf<Long>()
            var terminals = 0
            for (response in pollResponses) {
                val array = JSONObject(response).optJSONArray("events") ?: continue
                for (index in 0 until array.length()) {
                    val event = array.getJSONObject(index)
                    sequences += event.getLong("eventSequence")
                    if (event.getString("phase") == "CLOSED" || event.getString("phase") == "FAILED") terminals++
                }
            }
            assertTrue("at least one event was polled: $sequences", sequences.isNotEmpty())
            for (index in 1 until sequences.size) {
                assertTrue(
                    "eventSequence is strictly increasing: $sequences",
                    sequences[index] > sequences[index - 1]
                )
            }
            assertEquals("exactly one terminal event was published", 1, terminals)

            // ---- the production reader half (TlsConnectionStore) ----------------
            val store = TlsConnectionStore(CAPTURE_ID)
            store.begin()
            for (response in pollResponses) store.recordPoll(response)
            val snapshot = store.snapshot()
            assertEquals("the store saw the accepted connection", 1L, snapshot.counts.accepted)
            assertEquals("and its passthrough", 1L, snapshot.counts.passthrough)
            assertEquals("and its close", 1L, snapshot.counts.closed)
            assertEquals("and nothing else", 0L, snapshot.counts.proxied)
            assertEquals("no failure", 0L, snapshot.counts.failed)
            assertEquals("the store mirrors the engine's accepted count",
                events.getLong("connectionsAccepted"), snapshot.counts.accepted)
            assertEquals("the store mirrors the engine's passthrough count",
                events.getLong("connectionsPassthrough"), snapshot.counts.passthrough)

            // recordEngineStats replaces, never accumulates: reading the same stats
            // twice must not double the traffic.
            assertTrue("the stats envelope must parse", store.recordEngineStats(statsJson))
            val once = store.snapshot().traffic.bytesToUpstream
            assertEquals("the engine's upstream bytes are the store's", events.getLong("bytesToUpstream"), once)
            assertTrue(store.recordEngineStats(statsJson))
            assertEquals("re-reading the same stats does not double the bytes",
                once, store.snapshot().traffic.bytesToUpstream)

            val captureStats = store.snapshot().toCaptureStats()
            assertEquals("the reader never claims decryption", 0L, captureStats.decryptedConnections)
            assertEquals("nor a QUIC claim it cannot make", 0L, captureStats.quicUndecryptedConnections)
            store.close()

            // ---- boundary: no secret material reaches a poll or stats response --
            val tokenText = token.toString(StandardCharsets.US_ASCII)
            for (payload in pollResponses + statsJson) {
                assertFalse("a poll/stats response must not carry a keylog line", payload.contains("CLIENT_RANDOM"))
                assertFalse("nor a private key", payload.contains("PRIVATE KEY"))
                assertFalse("nor the run's gateway token", payload.contains(tokenText))
            }
        } finally {
            privateKey.fill(0)
            certificate.fill(0)
            if (handle != 0L) {
                stopEngine(handle)
                val stale = assertThrows(IllegalStateException::class.java) { bridge.gatewayToken(handle) }
                assertEquals("STALE_GENERATION", stale.message)
            }
        }
    }

    /**
     * One authenticated CONNECT through the production SOCKS server, a plain HTTP
     * request, and the origin's answer. Every poll response is appended to
     * [pollResponses] so the event stream can be checked and replayed into the
     * store, and [phases] is this connection's complete sequence.
     */
    private fun throughSocks(
        channel: TlsGatewayChannel,
        handle: Long,
        network: Network,
        host: String,
        port: Int,
        pollResponses: MutableList<String>,
        phases: MutableList<String>
    ): String {
        val socks = DirectSocks5Server(
            prepareTcp = { throw IOException("the direct path is not part of this test") },
            prepareUdp = { },
            resolveHost = { name -> network.getAllByName(name) },

            tlsGateway = channel
        )
        try {
            val socksPort = socks.start()
            Socket(InetAddress.getByName("127.0.0.1"), socksPort).use { client ->
                client.soTimeout = CLIENT_TIMEOUT_MILLIS
                val output = DataOutputStream(client.getOutputStream())
                val input = DataInputStream(client.getInputStream())
                authenticate(output, input, socks.credentials)
                val address = InetAddress.getByName(host).address
                output.write(
                    byteArrayOf(
                        SOCKS_VERSION.toByte(),
                        COMMAND_CONNECT.toByte(),
                        0,
                        if (address.size == 4) ADDRESS_TYPE_IPV4.toByte() else ADDRESS_TYPE_IPV6.toByte()
                    ) + address + byteArrayOf((port ushr 8).toByte(), port.toByte())
                )
                output.flush()
                assertEquals(5, input.readUnsignedByte())
                assertEquals("the SOCKS hop must accept through the gateway", 0, input.readUnsignedByte())
                input.readUnsignedByte()
                when (val addressType = input.readUnsignedByte()) {
                    ADDRESS_TYPE_IPV4 -> ByteArray(4).also(input::readFully)
                    ADDRESS_TYPE_IPV6 -> ByteArray(16).also(input::readFully)
                    else -> throw AssertionError("Unexpected reply address type $addressType")
                }
                input.readUnsignedByte()
                input.readUnsignedByte()

                val request = "GET / HTTP/1.0\r\nHost: $host\r\nConnection: close\r\n\r\n"
                    .toByteArray(StandardCharsets.US_ASCII)
                output.write(request)
                output.flush()
                val response = input.readBytes().toString(StandardCharsets.US_ASCII)

                // The relay is a half-close relay (TLS-211): CLOSED is published
                // only once BOTH directions end, so the client has to signal its
                // own EOF before the poll below can reach a terminal state.
                client.shutdownOutput()

                pollUntilTerminal(handle, pollResponses, phases)
                return response
            }
        } finally {
            socks.close()
        }
    }

    /** Polls the engine, collecting raw responses, until a terminal phase is seen. */
    private fun pollUntilTerminal(handle: Long, pollResponses: MutableList<String>, phases: MutableList<String>) {
        val deadline = SystemClock.elapsedRealtime() + TERMINAL_DEADLINE_MILLIS
        while (SystemClock.elapsedRealtime() < deadline) {
            val response = bridge.poll(handle, 128)
            pollResponses += response
            val array = JSONObject(response).optJSONArray("events")
            if (array != null) {
                for (index in 0 until array.length()) {
                    phases += array.getJSONObject(index).getString("phase")
                }
            }
            if (phases.lastOrNull() == "CLOSED" || phases.lastOrNull() == "FAILED") break
            Thread.sleep(POLL_INTERVAL_MILLIS)
        }
    }

    private fun authenticate(output: DataOutputStream, input: DataInputStream, credentials: SocksCredentials) {
        output.write(byteArrayOf(SOCKS_VERSION.toByte(), 1, METHOD_USERNAME_PASSWORD.toByte()))
        output.flush()
        assertEquals(5, input.readUnsignedByte())
        assertEquals("the server must select username/password", METHOD_USERNAME_PASSWORD, input.readUnsignedByte())
        val user = credentials.username.toByteArray(StandardCharsets.US_ASCII)
        val password = credentials.password.toByteArray(StandardCharsets.US_ASCII)
        output.writeByte(1)
        output.writeByte(user.size)
        output.write(user)
        output.writeByte(password.size)
        output.write(password)
        output.flush()
        assertEquals(1, input.readUnsignedByte())
        assertEquals(0, input.readUnsignedByte())
    }

    private fun stopEngine(handle: Long) {
        val deadline = SystemClock.elapsedRealtime() + STOP_DEADLINE_MILLIS
        while (true) {
            val stopped = JSONObject(bridge.stop(handle, 5_000))
            if (stopped.getBoolean("success")) return
            // A NOT_READY stop means shutdown is still draining (TLS-213): the
            // caller keeps the callback context and retries.
            assertTrue("the engine must stop: $stopped", SystemClock.elapsedRealtime() < deadline)
            Thread.sleep(POLL_INTERVAL_MILLIS)
        }
    }

    @Suppress("DEPRECATION")
    private fun physicalNetwork(): Network? {
        val active = connectivity.activeNetwork
        val physical = connectivity.allNetworks.filter { network ->
            connectivity.getNetworkCapabilities(network)
                ?.hasTransport(NetworkCapabilities.TRANSPORT_VPN) == false
        }
        return physical.firstOrNull { it == active }
            ?: physical.firstOrNull { network ->
                connectivity.getNetworkCapabilities(network)
                    ?.hasCapability(NetworkCapabilities.NET_CAPABILITY_VALIDATED) == true
            }
            ?: physical.firstOrNull { network ->
                connectivity.getNetworkCapabilities(network)
                    ?.hasCapability(NetworkCapabilities.NET_CAPABILITY_INTERNET) == true
            }
            ?: physical.firstOrNull()
    }

    private companion object {
        const val CAPTURE_ID = "tls-212-capacity-stats"
        const val DEFAULT_HTTP_PORT = 18_080
        const val CLIENT_TIMEOUT_MILLIS = 20_000
        const val POLL_INTERVAL_MILLIS = 50L
        const val TERMINAL_DEADLINE_MILLIS = 10_000L
        const val STOP_DEADLINE_MILLIS = 15_000L
        const val SOCKS_VERSION = 5
        const val COMMAND_CONNECT = 1
        const val ADDRESS_TYPE_IPV4 = 1
        const val ADDRESS_TYPE_IPV6 = 4
        const val METHOD_USERNAME_PASSWORD = 2
    }
}
