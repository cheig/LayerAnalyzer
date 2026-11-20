package com.example.layanalyzer

import android.content.ComponentName
import android.content.Context
import android.content.Intent
import android.content.ServiceConnection
import android.net.VpnService
import android.net.ConnectivityManager
import android.net.NetworkCapabilities
import android.os.Build
import android.os.IBinder
import android.os.SystemClock
import android.util.Base64
import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.platform.app.InstrumentationRegistry
import com.example.layanalyzer.capture.socks.SocksNioFixtureVpnService
import com.example.layanalyzer.capture.LiveCaptureStore
import com.example.layanalyzer.capture.tls.TlsCaptureState
import java.io.ByteArrayOutputStream
import java.net.InetSocketAddress
import java.net.Socket
import java.net.SocketException
import java.nio.ByteBuffer
import java.nio.ByteOrder
import java.security.KeyStore
import java.security.cert.CertificateFactory
import java.util.concurrent.CountDownLatch
import java.util.concurrent.TimeUnit
import javax.net.ssl.SNIHostName
import javax.net.ssl.SSLContext
import javax.net.ssl.SSLSocket
import javax.net.ssl.TrustManagerFactory
import org.json.JSONObject
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test
import org.junit.runner.RunWith

@RunWith(AndroidJUnit4::class)
class SocksNioTlsPcapTest {
    @Test(timeout = 90000)
    fun trustedTls13ThroughHevAndNioDecryptsOnlyWithDownstreamLease() {
        assertEquals("API36 only; NOT_RUN is not PASS", 36, Build.VERSION.SDK_INT)
        assertTrue(BuildConfig.TLS_ENABLED)
        assertFalse(BuildConfig.TLS_PROBE_ENABLED)
        NativeTestSupport.awaitApplicationEngine()
        val instrumentation = InstrumentationRegistry.getInstrumentation()
        val context = instrumentation.targetContext
        assertNull("Grant VPN consent explicitly before running", VpnService.prepare(context))
        val arguments = InstrumentationRegistry.getArguments()
        val host = checkNotNull(arguments.getString("nio305Host"))
        val port = checkNotNull(arguments.getString("nio305Port")).toInt()
        val root = Base64.decode(checkNotNull(arguments.getString("nio305RootDer")), Base64.NO_WRAP)
        val body = Base64.decode(checkNotNull(arguments.getString("nio305Body")), Base64.NO_WRAP)
        require(root.size in 1..16384 && body.size in 16..4096 && port in 1..65535)
        assertFalse(LiveCaptureStore.state.value.isCapturing)
        val bound = CountDownLatch(1)
        var service: SocksNioFixtureVpnService? = null
        val connection = object : ServiceConnection {
            override fun onServiceConnected(name: ComponentName, binder: IBinder) {
                service = (binder as SocksNioFixtureVpnService.FixtureBinder).service
                bound.countDown()
            }
            override fun onServiceDisconnected(name: ComponentName) = Unit
        }
        assertTrue(context.bindService(Intent(context, SocksNioFixtureVpnService::class.java)
            .setAction(SocksNioFixtureVpnService.FIXTURE_ACTION), connection, Context.BIND_AUTO_CREATE))
        try {
            assertTrue("Fixture service bind timeout", bound.await(10, TimeUnit.SECONDS))
            val fixture = checkNotNull(service).startFixture(host, port, root)
            var state: TlsCaptureState? = null
            var forwardingFailure: Throwable? = null
            try {
                val store = KeyStore.getInstance(KeyStore.getDefaultType()).apply {
                    load(null)
                    setCertificateEntry("proxy", CertificateFactory.getInstance("X.509")
                        .generateCertificate(fixture.proxyRoot.inputStream()))
                }
                val trust = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm()).apply { init(store) }
                val ssl = SSLContext.getInstance("TLS").apply { init(null, trust.trustManagers, null) }
                val raw = Socket()
                raw.use {
                    bindFixtureNetwork(context, raw)
                    raw.connect(InetSocketAddress(host, port), 10000)
                    (ssl.socketFactory.createSocket(raw, "upstream.fixture.test", port, true) as SSLSocket).use { peer ->
                        peer.soTimeout = 15000
                        peer.enabledProtocols = arrayOf("TLSv1.3")
                        peer.sslParameters = peer.sslParameters.apply {
                            endpointIdentificationAlgorithm = "HTTPS"
                            serverNames = listOf(SNIHostName("upstream.fixture.test"))
                        }
                        peer.startHandshake()
                        assertEquals("TLSv1.3", peer.session.protocol)
                        peer.outputStream.write(REQUEST)
                        peer.outputStream.flush()
                        val received = ByteArrayOutputStream()
                        val chunk = ByteArray(4096)
                        while (true) {
                            val count = peer.inputStream.read(chunk)
                            if (count < 0) break
                            received.write(chunk, 0, count)
                            assertTrue(received.size() <= 65536)
                        }
                        assertArrayEquals(response(body), received.toByteArray())
                    }
                }
                checkNotNull(service).awaitPacketDrain()
            } catch (failure: Throwable) {
                forwardingFailure = failure
                throw failure
            } finally {
                try { state = checkNotNull(service).stopFixture() } catch (cleanup: Throwable) {
                    if (forwardingFailure != null) forwardingFailure.addSuppressed(cleanup) else throw cleanup
                }
                forwardingFailure?.addSuppressed(AssertionError("NIO=${service?.nioStats()}; TLS=$state"))
            }
            assertNotNull(state)
            val stopped = checkNotNull(state)
            assertTrue(stopped.secretsComplete)
            assertNull(stopped.errorCode)
            assertEquals(1L, stopped.connections.proxied)
            assertEquals(0L, stopped.connections.failed)
            assertEquals(0L, stopped.connections.passthrough)
            assertTrue(stopped.connections.secretRecordsPersisted > 0)
            assertEquals(stopped.connections.secretRecordsAccepted, stopped.connections.secretRecordsPersisted)
            assertTrue(checkNotNull(service).fixtureStopped)
            val nio = checkNotNull(service?.nioStats())
            val admission = checkNotNull(nio.server.admission)
            val gateway = checkNotNull(nio.gateway)
            assertEquals(64, admission.tcp.limit)
            assertEquals(2, nio.eventLoopThreadLimit)
            assertEquals(1L, nio.server.acceptedClients)
            assertEquals(0L, nio.server.rejectedAdmissions)
            assertEquals(0L, nio.server.rejectedTransfers)
            assertEquals(1L, gateway.attempts)
            assertEquals(1L, gateway.ready)
            assertEquals(1L, nio.gatewayRelays)
            assertEquals(0L, gateway.failures.values.sum())
            assertEquals(0L, gateway.refusals)
            assertEquals(0L, gateway.timeouts)
            assertEquals(0, admission.handshakes.current + admission.tcp.current + admission.udp.current)
            assertEquals(0, admission.pendingReservations)
            assertTrue(admission.ownerLoads.all { it == 0 })
            assertEquals(0, checkNotNull(nio.buffers).reservedBytes)
            assertEquals(0, checkNotNull(nio.buffers).allocatedBytes)
            assertTrue(nio.server.loops.all {
                it.channels == 0 && it.keys == 0 && it.resources == 0 && it.timers == 0 &&
                    it.callbackFailures == 0L && it.cleanupFailures == 0L && it.failure == null
            })
            assertTrue(fixture.pcap.length() > 24)
            val capture = fixture.pcap.readBytes()
            assertFalse(contains(capture, body))
            val packetCounts = checkRawPackets(capture, host, port)
            val handle = NativeEngine.openFile(fixture.pcap.absolutePath, null)
            assertTrue(handle != 0L)
            try {
                success(NativeEngine.applyDecodeAs(handle, "tcp.port", port, "tls"))
                var generation = success(NativeEngine.configureTlsSecrets(handle, null, 1)).getLong("dissectionGeneration")
                assertUnavailable(NativeEngine.followTlsStream(handle, packetCounts.firstTcpPacketIndex, generation, 65536), body)
                fixture.secrets.acquireLease(fixture.captureId).use { lease ->
                    generation = lease.configureNative(
                        { generation = success(NativeEngine.configureTlsSecrets(handle, null, 3)).getLong("dissectionGeneration") },
                        { path -> success(NativeEngine.configureTlsSecrets(handle, path, 2)).getLong("dissectionGeneration") })
                    val followed = success(NativeEngine.followTlsStream(handle, packetCounts.firstTcpPacketIndex, generation, 65536))
                    assertFalse(followed.getBoolean("truncated"))
                    assertFalse(followed.getBoolean("incomplete"))
                    assertArrayEquals(REQUEST, streamBytes(followed.toString(), "client"))
                    assertArrayEquals(response(body), streamBytes(followed.toString(), "server"))
                }
                assertUnavailable(NativeEngine.followTlsStream(handle, packetCounts.firstTcpPacketIndex, generation, 65536), body)
            } finally { NativeEngine.closeFile(handle) }
            val evidence = JSONObject().put("task", "NIO-305").put("status", "PASS")
                .put("api", Build.VERSION.SDK_INT).put("protocol", "TLSv1.3")
                .put("mode", nio.mode).put("tcpBudget", admission.tcp.limit)
                .put("eventLoopLimit", nio.eventLoopThreadLimit).put("socksAccepted", nio.server.acceptedClients)
                .put("gatewayReady", gateway.ready).put("gatewayRelays", nio.gatewayRelays)
                .put("gatewayRefusals", gateway.refusals).put("gatewayFailures", gateway.failures.values.sum())
                .put("tlsProxied", stopped.connections.proxied).put("tlsHandshakeFailed", stopped.connections.handshakeFailed)
                .put("secretsAccepted", stopped.connections.secretRecordsAccepted)
                .put("secretsPersisted", stopped.connections.secretRecordsPersisted)
                .put("resourcesReleased", true)
                .put("pcapBytes", capture.size).put("bodyBytes", body.size)
                .put("tcpPackets", packetCounts.tcpPackets).put("ipv6ControlPackets", packetCounts.ipv6ControlPackets)
                .put("firstTcpPacketIndex", packetCounts.firstTcpPacketIndex)
                .put("withoutSecretsContainsBody", false).put("clearedSecretsContainsBody", false)
                .put("exactClientAndServerBytes", true).put("protectedHopsAbsent", true)
                .put("fixtureStopped", checkNotNull(service).fixtureStopped)
            java.io.File(context.filesDir, "nio305-result.json").writeText(evidence.toString())
        } finally {
            try { service?.stopFixture() } finally { context.unbindService(connection) }
        }
    }

    private fun bindFixtureNetwork(context: Context, socket: Socket) {
        val manager = context.getSystemService(ConnectivityManager::class.java)
        val deadline = SystemClock.elapsedRealtime() + 5000
        var failure: SocketException? = null
        while (SystemClock.elapsedRealtime() < deadline) {
            manager.allNetworks.firstOrNull { network ->
                manager.getNetworkCapabilities(network)?.hasTransport(NetworkCapabilities.TRANSPORT_VPN) == true &&
                    manager.getLinkProperties(network)?.linkAddresses?.any {
                        it.address.hostAddress == "10.77.0.2"
                    } == true
            }?.let { network ->
                try {
                    network.bindSocket(socket)
                    return
                } catch (error: SocketException) { failure = error }
            }
            SystemClock.sleep(20)
        }
        throw AssertionError("Fixture VPN route unavailable for ${context.packageName}, uid=${android.os.Process.myUid()}", failure)
    }

    private data class RawCaptureSummary(val tcpPackets: Int, val ipv6ControlPackets: Int, val firstTcpPacketIndex: Int)

    private fun checkRawPackets(capture: ByteArray, host: String, port: Int): RawCaptureSummary {
        val input = ByteBuffer.wrap(capture).order(ByteOrder.LITTLE_ENDIAN)
        assertEquals(0xa1b2c3d4.toInt(), input.int)
        input.position(20)
        assertEquals(101, input.int)
        val destination = java.net.InetAddress.getByName(host).address
        val client = byteArrayOf(10, 77, 0, 2)
        var packets = 0
        var ipv6ControlPackets = 0
        var firstTcpPacketIndex = -1
        while (input.hasRemaining()) {
            assertTrue(input.remaining() >= 16)
            input.position(input.position() + 8)
            val length = input.int
            assertEquals(length, input.int)
            assertTrue(length in 40..65535 && input.remaining() >= length)
            val packet = ByteArray(length).also { input.get(it) }
            if ((packet[0].toInt() and 0xff) ushr 4 == 6) {
                checkIpv6Control(packet)
                ipv6ControlPackets++
                continue
            }
            assertEquals(4, (packet[0].toInt() and 0xff) ushr 4)
            assertEquals(6, packet[9].toInt())
            if (firstTcpPacketIndex < 0) firstTcpPacketIndex = packets + ipv6ControlPackets
            val source = packet.copyOfRange(12, 16)
            val target = packet.copyOfRange(16, 20)
            val header = (packet[0].toInt() and 15) * 4
            val tcp = ByteBuffer.wrap(packet).order(ByteOrder.BIG_ENDIAN)
            val sourcePort = tcp.getShort(header).toInt() and 65535
            val targetPort = tcp.getShort(header + 2).toInt() and 65535
            if (source.contentEquals(client)) {
                assertArrayEquals(destination, target)
                assertEquals(port, targetPort)
            } else {
                assertArrayEquals(destination, source)
                assertArrayEquals(client, target)
                assertEquals(port, sourcePort)
            }
            packets++
        }
        assertTrue(packets > 0)
        return RawCaptureSummary(packets, ipv6ControlPackets, firstTcpPacketIndex)
    }

    private fun checkIpv6Control(packet: ByteArray) {
        assertTrue(packet.size >= 48)
        assertEquals(packet.size - 40, ByteBuffer.wrap(packet).getShort(4).toInt() and 65535)
        val source = java.net.InetAddress.getByAddress(packet.copyOfRange(8, 24))
        val destination = packet.copyOfRange(24, 40)
        assertTrue(source.isLinkLocalAddress || source.isAnyLocalAddress)
        val offset = if (packet[6].toInt() == 0) {
            assertTrue(packet.size >= 56)
            assertEquals(1, packet[7].toInt())
            assertEquals(58, packet[40].toInt())
            assertEquals(0, packet[41].toInt())
            assertArrayEquals(java.net.InetAddress.getByName("ff02::16").address, destination)
            assertEquals(143, packet[48].toInt() and 255)
            48
        } else {
            assertEquals("Unexpected IPv6 application traffic", 58, packet[6].toInt())
            assertEquals(255, packet[7].toInt() and 255)
            when (packet[40].toInt() and 255) {
                133 -> assertArrayEquals(java.net.InetAddress.getByName("ff02::2").address, destination)
                135 -> {
                    assertTrue(packet.size >= 64 && source.isAnyLocalAddress)
                    assertArrayEquals(java.net.InetAddress.getByName("::1").address, packet.copyOfRange(48, 64))
                    val solicited = java.net.InetAddress.getByName("ff02::1:ff00:0").address
                    packet.copyInto(solicited, 13, 61, 64)
                    assertArrayEquals(solicited, destination)
                }
                else -> error("Unexpected ICMPv6 type")
            }
            40
        }
        assertEquals(0, packet[offset + 1].toInt())
    }

    private fun streamBytes(raw: String, direction: String): ByteArray {
        val records = JSONObject(raw).optJSONArray("records") ?: return byteArrayOf()
        return ByteArrayOutputStream().also { output ->
            for (index in 0 until records.length()) {
                val record = records.getJSONObject(index)
                if (record.getString("direction") == direction)
                    output.write(Base64.decode(record.getString("bytesBase64"), Base64.NO_WRAP))
            }
        }.toByteArray()
    }

    private fun success(raw: String) = JSONObject(raw).also { assertTrue(raw, it.getBoolean("success")) }
    private fun assertUnavailable(raw: String, body: ByteArray) {
        val result = JSONObject(raw)
        assertFalse(raw, result.getBoolean("success"))
        assertEquals(raw, "NOT_READY", result.getString("errorCode"))
        assertFalse(contains(streamBytes(raw, "server"), body))
    }
    private fun contains(bytes: ByteArray, value: ByteArray) = value.isNotEmpty() &&
        (0..bytes.size - value.size).any { start -> value.indices.all { bytes[start + it] == value[it] } }
    private fun response(body: ByteArray) =
        "HTTP/1.1 200 OK\r\nContent-Length: ${body.size}\r\nConnection: close\r\n\r\n".toByteArray() + body

    companion object {
        private val REQUEST = "GET /nio305 HTTP/1.1\r\nHost: upstream.fixture.test\r\nConnection: close\r\n\r\n".toByteArray()
    }
}
