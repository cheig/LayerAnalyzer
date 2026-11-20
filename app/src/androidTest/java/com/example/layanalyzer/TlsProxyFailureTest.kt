package com.example.layanalyzer

import android.content.Context
import android.net.ConnectivityManager
import android.net.Network
import android.net.NetworkCapabilities
import android.os.SystemClock
import android.util.Log
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
import java.net.InetSocketAddress
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
 * TLS-217 on a device: the proxy's failure state machine over the **real Go
 * engine**, reachable with the same controlled host fixture the gateway test
 * uses. Two boundaries are exercised end to end:
 *
 *  - a plaintext (STARTTLS-style) preamble: the engine must classify it as not
 *    TLS and pass it through, producing no interception and no secret;
 *  - an origin that cannot be opened: the engine must fail the connection
 *    promptly and hand nothing a success, again with no secret.
 *
 * The success-path TUN decryption is covered by TlsVpnDecryptionTest. HRR and
 * mTLS are covered by the host Go suite; real ECH and KeyUpdate peers exercise
 * the device engine in TlsProtocolBoundaryTest.
 * This file is a device gate, not a host test: it needs an attached device and a
 * reachable fixture. There is no Assume — a missing fixture argument or an
 * unreachable fixture is a failed gate, and the evidence for this class records
 * it as NOT RUN until a device is attached. TLS must be enabled: an OFF-build
 * refusal is not evidence that the production failure paths ran.
 */
@RunWith(AndroidJUnit4::class)
class TlsProxyFailureTest {
    private val context = ApplicationProvider.getApplicationContext<Context>()
    private val connectivity = context.getSystemService(ConnectivityManager::class.java)
    private val arguments = InstrumentationRegistry.getArguments()
    private val bridge = TlsProxyBridge()
    private val secretOffers = AtomicInteger()
    private val preparedSockets = AtomicInteger()
    private val directAttempts = AtomicInteger()

    @Test
    fun aPlaintextPreambleIsPassedThroughAndProducesNoSecret() {
        withEngine { handle, channel, host, port ->
            // A STARTTLS-shaped first line: not TLS, so it must not be probed
            // into a handshake.
            val phases = mutableListOf<String>()
            val reply = throughSocks(channel, host, port) { output ->
                val preamble = "EHLO client.example.test\r\n".toByteArray(StandardCharsets.US_ASCII)
                output.write(preamble)
                output.flush()
            }.also { phases += pollPhases(handle) }

            assertTrue("the HTTP fixture must reject the EHLO preamble", reply.startsWith("<!DOCTYPE HTML>"))
            assertTrue("the HTTP fixture received EHLO", reply.contains("EHLO"))
            assertTrue("the engine accepted the connection: $phases", phases.contains("ACCEPTED"))
            assertTrue("it probed it: $phases", phases.contains("SNIFFING"))
            assertTrue("it passed it through: $phases", phases.contains("PASSTHROUGH"))
            assertFalse("nothing was intercepted: $phases", phases.contains("RELAYING"))
            assertFalse("no downstream handshake: $phases", phases.contains("DOWNSTREAM_HANDSHAKE"))
            assertFalse("no upstream handshake: $phases", phases.contains("UPSTREAM_HANDSHAKE"))
            assertEquals("exactly one terminal state: $phases", "CLOSED", phases.last())
            assertEquals("exactly one terminal event", 1, phases.count { it == "CLOSED" || it == "FAILED" })
            assertEquals("one upstream socket, no replay", 1, preparedSockets.get())
            assertEquals("a non-TLS connection produces no secret", 0, secretOffers.get())
            assertPassthroughStats(handle)
            Log.i(TAG, "plaintext phases=$phases prepared=${preparedSockets.get()} secretOffers=${secretOffers.get()}")
        }
    }

    @Test
    fun anUnreachableOriginFailsPromptlyWithoutASecret() {
        withEngine { handle, channel, host, port ->
            // The production NIO server owns its gateway and closes it on stop.
            // Recovery must happen within one running server, not a closed channel.
            createSocks(channel).use { socks ->
                val running = socks to socks.start()
                val started = SystemClock.elapsedRealtime()
                // A destination on the same controlled host that nothing is listening
                // on: the gateway's upstream dial cannot succeed, so the SOCKS hop
                // must be told so rather than given a success it cannot back.
                val refused = connectAndReadReply(channel, host, unreachablePort(), running)
                assertFalse("nothing was listening, so the hop must not succeed: $refused", refused.success)
                val elapsed = SystemClock.elapsedRealtime() - started
                assertTrue("the failure must arrive promptly", elapsed < PROMPT_MILLIS)
                assertEquals("the refusal must come from a real Go upstream dial", 1, preparedSockets.get())
                assertEquals("the SOCKS direct path must not manufacture the refusal", 0, directAttempts.get())
                val stats = JSONObject(bridge.stats(handle)).getJSONObject("events")
                assertEquals("a refused origin produces no secret", 0L, stats.getLong("secretRecordsAccepted"))
                assertEquals("no TLS connection was proxied", 0L, stats.getLong("connectionsProxied"))
                assertEquals("no secret callback on refusal", 0, secretOffers.get())

                // A failed dial must release its reservation and leave this same
                // engine able to serve the next independent request.
                val reply = throughSocks(channel, host, port, running) { output ->
                    output.write("GET /index.html HTTP/1.0\r\nHost: fixture\r\n\r\n".toByteArray(StandardCharsets.US_ASCII))
                    output.flush()
                }
                assertTrue("a subsequent request must succeed", reply.startsWith("HTTP/1.0 200"))
                val phases = pollPhases(handle)
                assertEquals(listOf("ACCEPTED", "SNIFFING", "PASSTHROUGH", "CLOSED"), phases)
                assertEquals("one refused dial and one recovery dial", 2, preparedSockets.get())
                assertPassthroughStats(handle)
                Log.i(TAG, "refused elapsedMillis=$elapsed recoveryPhases=$phases prepared=${preparedSockets.get()} secretOffers=${secretOffers.get()}")
            }
        }
    }

    /**
     * Runs one engine and hands the body the run's setup: a started engine, its
     * production channel, the fixture host and the candidate port. The engine is
     * always stopped, and the stop is asserted to have released its listener.
     */
    private fun withEngine(body: (handle: Long, channel: TlsGatewayChannel, host: String, port: Int) -> Unit) {
        assertTrue("TLS-217 device evidence requires a TLS ON build", BuildConfig.TLS_ENABLED)

        val host = requireNotNull(arguments.getString("hostGateway")) {
            "Required fixture argument: hostGateway — a host reachable from the device " +
                "(10.0.2.2 on an emulator, a controlled LAN address on a real device)"
        }
        val port = (arguments.getString("hostHttpPort") ?: DEFAULT_HTTP_PORT.toString()).toInt()
        require(port in 1..65535 && unreachablePort() in 1..65535 && port != unreachablePort()) {
            "The fixture and closed ports must be valid and distinct"
        }
        val generation = 1L
        val network = requireNotNull(physicalNetwork()) {
            "The device has no physical network; the gateway dials the captured network only"
        }
        val protector = UpstreamSocketProtector(
            { UpstreamSocketProtector.NetworkSnapshot(network, generation) },
            // No VPN is active in the failure cases, so there is nothing to exclude.
            { true }
        )
        val callbacks = object : TlsPlatformCallbacks {
            override fun prepareSocket(fd: Int, networkGeneration: Long): String =
                protector.prepareSocket(fd, networkGeneration).also { result ->
                    if (JSONObject(result).getBoolean("success")) preparedSockets.incrementAndGet()
                }

            override fun resolveHost(host: String, networkGeneration: Long): String =
                protector.resolveHost(host, networkGeneration)

            override fun verifyUpstream(
                chainDer: Array<ByteArray>,
                identity: String,
                authType: String,
                tlsVersion: String
            ): String = AndroidUpstreamTrustVerifier()
                .verifyUpstream(chainDer, identity, authType, tlsVersion)

            override fun offerSecret(captureId: String, connectionId: String, line: ByteArray): Boolean {
                secretOffers.incrementAndGet()
                line.fill(0)
                return false
            }
        }

        val policy = TlsRoutingPolicy.freeze(
            TlsCaptureSettings(enabled = true, candidatePorts = setOf(port, unreachablePort()))
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
        var gatewayPort = 0
        try {
            val started = JSONObject(bridge.start(config, certificate, privateKey, callbacks))
            assertTrue("the engine must start for an enabled policy: $started", started.getBoolean("success"))
            handle = started.getLong("engineHandle")
            gatewayPort = started.getInt("port")
            val channel = TlsGatewayChannel(
                gatewayPort = gatewayPort,
                token = bridge.gatewayToken(handle),
                captureId = CAPTURE_ID,
                networkGeneration = generation,
                policy = policy,
                prepareHopSocket = { }
            )
            try {
                body(handle, channel, host, port)
                assertEquals("no direct fallback", 0, directAttempts.get())
            } finally {
                channel.close()
                assertFalse("the channel wipes its token", channel.carriesTokenMaterial())
            }
        } finally {
            privateKey.fill(0)
            certificate.fill(0)
            if (handle != 0L) {
                stopEngine(handle)
                val stale = assertThrows(IllegalStateException::class.java) { bridge.gatewayToken(handle) }
                assertEquals("STALE_GENERATION", stale.message)
                assertThrows("stop must release the gateway listener", IOException::class.java) {
                    Socket().use { it.connect(InetSocketAddress("127.0.0.1", gatewayPort), 1_000) }
                }
                assertEquals("no late secret callback after stop", 0, secretOffers.get())
                Log.i(TAG, "stopped listenerClosed=true staleHandle=true secretOffers=${secretOffers.get()}")
            }
        }
    }

    /**
     * One authenticated CONNECT through the production SOCKS server and the
     * engine's gateway. The caller writes the request bytes; the reply is read to
     * end of stream. A request that never reaches the engine is a failure of this
     * helper, not a pass.
     */
    private fun throughSocks(
        channel: TlsGatewayChannel,
        host: String,
        port: Int,
        running: Pair<DirectSocks5Server, Int>? = null,
        request: (DataOutputStream) -> Unit
    ): String {
        val socks = running?.first ?: createSocks(channel)
        try {
            val socksPort = running?.second ?: socks.start()
            Socket(InetAddress.getByName("127.0.0.1"), socksPort).use { client ->
                client.soTimeout = CLIENT_TIMEOUT_MILLIS
                val output = DataOutputStream(client.getOutputStream())
                val input = DataInputStream(client.getInputStream())
                authenticate(output, input, socks.credentials)
                writeConnect(output, InetAddress.getByName(host).address, port)
                val reply = readSocksReply(input)
                assertTrue("the SOCKS hop must accept through the gateway", reply.success)
                request(output)
                // The relay half-closes only once the client's write side ends;
                // a passthrough connection reaches CLOSED only after that.
                client.shutdownOutput()
                return input.readBytes().toString(StandardCharsets.US_ASCII)
            }
        } finally {
            if (running == null) socks.close()
        }
    }

    /** One CONNECT that is expected to be refused by the gateway. */
    private fun connectAndReadReply(channel: TlsGatewayChannel, host: String, port: Int,
        running: Pair<DirectSocks5Server, Int>? = null): SocksReply {
        val socks = running?.first ?: createSocks(channel)
        try {
            val socksPort = running?.second ?: socks.start()
            Socket(InetAddress.getByName("127.0.0.1"), socksPort).use { client ->
                client.soTimeout = CLIENT_TIMEOUT_MILLIS
                val output = DataOutputStream(client.getOutputStream())
                val input = DataInputStream(client.getInputStream())
                authenticate(output, input, socks.credentials)
                writeConnect(output, InetAddress.getByName(host).address, port)
                return readSocksReply(input)
            }
        } finally {
            if (running == null) socks.close()
        }
    }

    private fun createSocks(channel: TlsGatewayChannel) = DirectSocks5Server(
        prepareTcp = { rejectDirectPath() }, prepareUdp = { },
        resolveHost = { name -> network().getAllByName(name) }, tlsGateway = channel
    )

    private fun writeConnect(output: DataOutputStream, address: ByteArray, port: Int) {
        output.write(
            byteArrayOf(
                SOCKS_VERSION.toByte(),
                COMMAND_CONNECT.toByte(),
                0,
                if (address.size == 4) ADDRESS_TYPE_IPV4.toByte() else ADDRESS_TYPE_IPV6.toByte()
            ) + address + byteArrayOf((port ushr 8).toByte(), port.toByte())
        )
        output.flush()
    }

    /** The SOCKS reply's status and its address/port fields. */
    private fun readSocksReply(input: DataInputStream): SocksReply {
        val version = input.readUnsignedByte()
        assertEquals("a valid SOCKS reply is required", SOCKS_VERSION, version)
        val status = input.readUnsignedByte()
        input.readUnsignedByte()
        when (val addressType = input.readUnsignedByte()) {
            ADDRESS_TYPE_IPV4 -> ByteArray(4).also(input::readFully)
            ADDRESS_TYPE_IPV6 -> ByteArray(16).also(input::readFully)
            else -> throw AssertionError("Unexpected reply address type $addressType")
        }
        input.readUnsignedByte()
        input.readUnsignedByte()
        return SocksReply(version == SOCKS_VERSION && status == 0)
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

    /** The phases published for the one connection a case made, until its terminal state. */
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

    private fun stopEngine(handle: Long) {
        val deadline = SystemClock.elapsedRealtime() + STOP_DEADLINE_MILLIS
        while (true) {
            val stopped = JSONObject(bridge.stop(handle, 5_000))
            if (stopped.getBoolean("success")) return
            assertTrue("the engine must stop: $stopped", SystemClock.elapsedRealtime() < deadline)
            Thread.sleep(POLL_INTERVAL_MILLIS)
        }
    }

    private fun unreachablePort(): Int =
        (arguments.getString("hostClosedPort") ?: DEFAULT_CLOSED_PORT.toString()).toInt()

    private fun rejectDirectPath(): Nothing {
        directAttempts.incrementAndGet()
        throw IOException("the direct path is not part of this test")
    }

    private fun assertPassthroughStats(handle: Long) {
        val stats = JSONObject(bridge.stats(handle)).getJSONObject("events")
        assertEquals(1L, stats.getLong("connectionsPassthrough"))
        assertEquals(0L, stats.getLong("connectionsProxied"))
        assertEquals(0L, stats.getLong("secretRecordsAccepted"))
        assertEquals(0L, stats.getLong("secretRecordsPersisted"))
        assertEquals(0, secretOffers.get())
    }

    private fun network(): Network = requireNotNull(physicalNetwork()) {
        "The device has no physical network"
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

    private data class SocksReply(val success: Boolean)

    private companion object {
        const val TAG = "TLS-217"
        const val CAPTURE_ID = "tls-217-failure"
        const val DEFAULT_HTTP_PORT = 18_080
        // A port on the controlled host that nothing is expected to listen on.
        const val DEFAULT_CLOSED_PORT = 9
        const val CLIENT_TIMEOUT_MILLIS = 20_000
        // C10 permits a full 10 s upstream connect timeout. A silently dropped
        // SYN is still a valid unreachable origin; allow 3 s for JNI/SOCKS and
        // scheduling instead of requiring completion before that budget ends.
        const val PROMPT_MILLIS = 13_000L
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
