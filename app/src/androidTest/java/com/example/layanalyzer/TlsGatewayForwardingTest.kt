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
 * TLS-215 on a device: the SOCKS hop's CONNECT reaches the **real Go engine**
 * over the production channel, and a connection the engine does not intercept is
 * forwarded byte for byte.
 *
 * The destination is the controlled host fixture the live-capture test already
 * uses (`hostGateway`, default 10.0.2.2 on an emulator; `hostHttpPort`, default
 * 18080) — a plain HTTP origin, deliberately *not* TLS. The engine therefore
 * probes it, decides `not_tls`, and passes it through, which is exactly the path
 * this card added: the `LAT1` frame, the run's token, the READY ordering, the
 * real upstream dial and the engine's own event stream are all exercised without
 * needing a decrypted payload. No Assume: a missing fixture argument or a device
 * with no network is an unfulfilled gate, not a pass.
 *
 * What this test deliberately does **not** claim: no VPN is established here, so
 * `VpnService.protect` cannot be called and the protect callback is injected as
 * `{ true }` (nothing needs excluding without a VPN). Protect/bind-before-connect
 * under an active VPN remains the TLS-203 device gate, and TLS-218 re-runs this
 * end to end with the VPN up.
 */
@RunWith(AndroidJUnit4::class)
class TlsGatewayForwardingTest {
    private val context = ApplicationProvider.getApplicationContext<Context>()
    private val connectivity = context.getSystemService(ConnectivityManager::class.java)
    private val arguments = InstrumentationRegistry.getArguments()
    private val bridge = TlsProxyBridge()

    @Test
    fun aPassthroughConnectionTravelsThroughTheProductionGateway() {
        if (!BuildConfig.TLS_ENABLED) {
            // Without the build switch there is no engine and no token to read;
            // the only honest assertion is that the boundary refuses to pretend.
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
            // connection never calls it, and a run that did intercept would be
            // checked against the device's own trust store.
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
            assertTrue(gatewayPort in 1..65535)
            assertFalse("the start result must not echo the token", started.has("token"))

            val token = bridge.gatewayToken(handle)
            assertEquals("the token is 32 random bytes in base64url", 43, token.size)

            val channel = TlsGatewayChannel(
                gatewayPort = gatewayPort,
                token = token,
                captureId = CAPTURE_ID,
                networkGeneration = generation,
                policy = policy,
                prepareHopSocket = { }
            )
            try {
                val phases = mutableListOf<String>()
                val response = throughSocks(channel, handle, network, host, port, phases)

                assertTrue("the origin must answer through the gateway: $response", response.startsWith("HTTP/1."))
                assertTrue("a 200 from the fixture origin: $response", response.contains("200"))
                assertEquals("no connection may be intercepted here", 0, secretOffers.get())

                assertTrue("the engine accepted the connection: $phases", phases.contains("ACCEPTED"))
                assertTrue("it probed it: $phases", phases.contains("SNIFFING"))
                assertTrue("it passed it through: $phases", phases.contains("PASSTHROUGH"))
                assertFalse("nothing was intercepted: $phases", phases.contains("RELAYING"))
                assertFalse("no downstream handshake: $phases", phases.contains("DOWNSTREAM_HANDSHAKE"))
                assertFalse("no upstream handshake either: $phases", phases.contains("UPSTREAM_HANDSHAKE"))
                assertEquals("exactly one terminal state: $phases", "CLOSED", phases.last())

                val stats = JSONObject(bridge.stats(handle)).getJSONObject("events")
                assertEquals("one connection was accepted", 1L, stats.getLong("connectionsAccepted"))
                assertEquals("it was passed through", 1L, stats.getLong("connectionsPassthrough"))
                assertEquals("nothing was proxied", 0L, stats.getLong("connectionsProxied"))
                assertEquals("nothing failed", 0L, stats.getLong("connectionsFailed"))
                assertEquals("no secret was produced", 0L, stats.getLong("secretRecordsAccepted"))
                assertTrue("the relay carried the request upstream", stats.getLong("bytesToUpstream") > 0L)
                assertTrue("and the answer back", stats.getLong("bytesToDownstream") > 0L)
            } finally {
                channel.close()
                assertFalse("the channel wipes its token", channel.carriesTokenMaterial())
                assertThrows(IOException::class.java) { channel.describe(InetAddress.getByName(host), port) }
            }
        } finally {
            privateKey.fill(0)
            certificate.fill(0)
            if (handle != 0L) {
                stopEngine(handle)
                // A stopped run has no token to hand out any more.
                val stale = assertThrows(IllegalStateException::class.java) { bridge.gatewayToken(handle) }
                assertEquals("STALE_GENERATION", stale.message)
            }
        }
    }

    /**
     * One authenticated CONNECT through the production SOCKS server, a plain HTTP
     * request, and the origin's answer. The engine's events are polled after the
     * connection is finished, so [phases] is this connection's complete sequence.
     */
    private fun throughSocks(
        channel: TlsGatewayChannel,
        handle: Long,
        network: Network,
        host: String,
        port: Int,
        phases: MutableList<String>
    ): String {
        val socks = DirectSocks5Server(
            // This test drives the gateway path only; an unclaimed connection
            // would need the VPN's protect callback (TLS-216) and is not part of
            // this card's claim.
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

                // The relay is a half-close relay (TLS-211): PASSTHROUGH is
                // published before it runs and the terminal CLOSED only once
                // BOTH directions end, so the client has to signal its own EOF
                // (which `Connection: close` already promises the origin)
                // before the phases below can be polled to a terminal state.
                // Polling with the write side still open showed
                // [ACCEPTED, SNIFFING, PASSTHROUGH] and burned the deadline on
                // both ABIs, which is the relay behaving correctly.
                client.shutdownOutput()

                phases += pollPhases(handle)
                return response
            }
        } finally {
            socks.close()
        }
    }

    /** The phases published for the one connection this test made, until its terminal state. */
    private fun pollPhases(handle: Long): List<String> {
        val phases = mutableListOf<String>()
        val deadline = SystemClock.elapsedRealtime() + TERMINAL_DEADLINE_MILLIS
        while (SystemClock.elapsedRealtime() < deadline) {
            val polled = JSONObject(bridge.poll(handle, 128))
            val events = polled.optJSONArray("events")
            if (events != null) {
                for (index in 0 until events.length()) {
                    phases += events.getJSONObject(index).getString("phase")
                }
            }
            if (phases.lastOrNull() == "CLOSED" || phases.lastOrNull() == "FAILED") break
            Thread.sleep(POLL_INTERVAL_MILLIS)
        }
        return phases
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
        const val CAPTURE_ID = "tls-215-gateway"
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
