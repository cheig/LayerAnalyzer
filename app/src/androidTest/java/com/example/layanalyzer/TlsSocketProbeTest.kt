package com.example.layanalyzer

import android.content.Context
import android.content.Intent
import android.net.ConnectivityManager
import android.net.NetworkCapabilities
import android.net.VpnService
import android.os.ParcelFileDescriptor
import android.os.SystemClock
import android.system.ErrnoException
import android.system.Os
import android.system.OsConstants
import androidx.core.content.ContextCompat
import androidx.test.core.app.ApplicationProvider
import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.platform.app.InstrumentationRegistry
import com.example.layanalyzer.capture.LiveCaptureStore
import com.example.layanalyzer.capture.LiveCaptureVpnService
import com.example.layanalyzer.capture.tls.UpstreamSocketProtector
import com.example.layanalyzer.capture.tls.UpstreamSocketProtector.NetworkSnapshot
import com.example.layanalyzer.capture.tls.UpstreamSocketProtector.Stage
import org.json.JSONObject
import org.junit.Assert.*
import org.junit.Before
import org.junit.Test
import org.junit.runner.RunWith
import java.io.DataInputStream
import java.io.File
import java.io.FileDescriptor
import java.io.IOException
import java.net.InetAddress
import java.net.InetSocketAddress
import java.net.ServerSocket
import java.net.Socket
import java.net.SocketTimeoutException
import java.util.concurrent.atomic.AtomicReference

/** No Assume: missing consent, fixture or IPv6 is an unfulfilled gate, not a pass. */
@RunWith(AndroidJUnit4::class)
class TlsSocketProbeTest {
    private val context = ApplicationProvider.getApplicationContext<Context>()
    private val connectivity = context.getSystemService(ConnectivityManager::class.java)

    @Before
    fun load() {
        assertTrue("Build with -PlayanalyzerTlsProbe=true", BuildConfig.TLS_PROBE_ENABLED)
        success(NativeEngine.loadTlsBridgeProbe(false, 1))
    }

    @Test
    fun failuresNeverConnectAndReleaseAllDescriptors() {
        val snapshot = physicalNetwork()
        ServerSocket(0, 8, InetAddress.getByName("127.0.0.1")).use { server ->
            server.soTimeout = 200
            fun invoke(callback: NativeEngine.TlsSocketProbeCallback, expected: String) {
                val result = JSONObject(NativeEngine.runTlsSocketProbe("127.0.0.1", server.localPort, 7, 1000, callback))
                assertFalse(result.toString(), result.getBoolean("success"))
                assertEquals(expected, result.getString("errorCode"))
                assertFalse(result.getBoolean("connected"))
                assertEquals(1, result.getInt("controlCalls"))
                assertEquals(0, result.getInt("serverAcceptSequence"))
            }
            fun invoke(protector: UpstreamSocketProtector, expected: String) =
                invoke(NativeEngine.TlsSocketProbeCallback(protector::prepareSocket), expected)
            // Warm the Go runtime / poller before measuring descriptors.
            val reject = UpstreamSocketProtector({ snapshot }, { fd -> assertUnconnected(fd); false })
            invoke(reject, "PROTECT_FAILED")
            val baseline = settledFdCount()
            repeat(20) {
                invoke(reject, "PROTECT_FAILED")
                assertEquals(listOf(Stage.Validated), reject.lastStages)
                invoke(UpstreamSocketProtector({ snapshot.copy(generation = 8) }, { fail("stale protect"); true }), "STALE_GENERATION")
                invoke(UpstreamSocketProtector({ null }, { fail("lost network protect"); true }), "NETWORK_CHANGED")
                var duplicate: FileDescriptor? = null
                val brokenBind = UpstreamSocketProtector({ snapshot }, { fd -> assertUnconnected(fd); true }, { _, fd ->
                    duplicate = fd
                    throw IOException("fixture-only exception must not cross JNI")
                })
                invoke(brokenBind, "IO_ERROR")
                assertFalse("dup leaked after binding exception", requireNotNull(duplicate).valid())
                assertEquals(Stage.DuplicateClosed, brokenBind.lastStages.last())
                val changing = AtomicReference<NetworkSnapshot?>(snapshot)
                invoke(UpstreamSocketProtector({ changing.get() }, { true }, { _, _ -> changing.set(null) }), "NETWORK_CHANGED")
                invoke(NativeEngine.TlsSocketProbeCallback { _, _ -> throw IllegalStateException("do not serialize") }, "IO_ERROR")
                invoke(NativeEngine.TlsSocketProbeCallback { _, _ -> "invalid json" }, "IO_ERROR")
            }
            try {
                server.accept().use { fail("A rejected preparation reached connect") }
            } catch (_: SocketTimeoutException) { /* expected: zero accepted sockets */ }
            assertTrue("FD count grew", settledFdCount() <= baseline)
            val state = success(NativeEngine.getTlsBridgeProbeState())
            assertEquals(0, state.getInt("globalRefs"))
            assertEquals(0, state.getInt("attachedThreads"))
            assertEquals(state.getLong("callbacksStarted"), state.getLong("callbacksCompleted"))
        }
    }

    @Test fun ipv4ProtectedBeforeConnectUnderSelfCapturingVpn() = exerciseVpn(false)
    @Test fun ipv6ProtectedBeforeConnectUnderSelfCapturingVpn() = exerciseVpn(true)

    private fun exerciseVpn(ipv6: Boolean) {
        val args = InstrumentationRegistry.getArguments()
        val key = if (ipv6) "tlsSocketIpv6" else "tlsSocketIpv4"
        val ip = requireNotNull(args.getString(key)) { "Required fixture argument: $key" }
        val address = requireNotNull(Os.inet_pton(if (ipv6) OsConstants.AF_INET6 else OsConstants.AF_INET, ip))
        val port = args.getString("tlsSocketPort", "18085").toInt()
        assertNull("Grant VPN consent on the dedicated test device first", VpnService.prepare(context))
        assertFalse("Do not interrupt an existing user capture", LiveCaptureStore.state.value.isCapturing)
        val snapshot = physicalNetwork()
        val protector = UpstreamSocketProtector(
            currentNetwork = {
                connectivity.getNetworkCapabilities(snapshot.network)?.takeIf {
                    !it.hasTransport(NetworkCapabilities.TRANSPORT_VPN)
                }?.let { snapshot }
            },
            // VpnService.protect(int) is Android's UID-scoped native API and
            // requires no Service context/binder. It uses this app's VPN grant.
            protect = { fd -> assertUnconnected(fd); VpnService().protect(fd) }
        )
        LiveCaptureStore.clearError()
        // Scope the capture to this app alone so `packetCount > 0` below really
        // means "the positive control entered TUN" — unrelated background
        // traffic must not be able to satisfy that wait.
        ContextCompat.startForegroundService(context, Intent(context, LiveCaptureVpnService::class.java).apply {
            putExtra(LiveCaptureVpnService.EXTRA_EXCLUDE_SELF, false)
            putExtra(LiveCaptureVpnService.EXTRA_CAPTURE_IPV6, ipv6)
            putStringArrayListExtra(LiveCaptureVpnService.EXTRA_ALLOWED_APPLICATIONS, arrayListOf(context.packageName))
        })
        try {
            waitUntil("VPN capture startup") { LiveCaptureStore.state.value.isCapturing || LiveCaptureStore.state.value.error != null }
            assertTrue(LiveCaptureStore.state.value.error, LiveCaptureStore.state.value.isCapturing)
            waitUntil("VPN transport") {
                connectivity.getNetworkCapabilities(connectivity.activeNetwork)?.hasTransport(NetworkCapabilities.TRANSPORT_VPN) == true
            }
            // Positive control: an ordinary self-owned socket must enter TUN.
            var sequence = Socket().use { socket ->
                socket.connect(InetSocketAddress(address, port), 10_000)
                socket.soTimeout = 10_000
                val reader = DataInputStream(socket.getInputStream())
                assertEquals(0x4c415331, reader.readInt())
                reader.readInt().toLong() and 0xffffffffL
            }
            waitUntil("self-owned socket was not captured") { LiveCaptureStore.state.value.packetCount > 0 }
            SystemClock.sleep(500)
            // First protected connection warms the Go network poller.
            fun dial() {
                val result = success(NativeEngine.runTlsSocketProbe(
                    ip, port, snapshot.generation, 10_000,
                    NativeEngine.TlsSocketProbeCallback(protector::prepareSocket)
                ))
                assertTrue(result.getBoolean("connected"))
                assertEquals(1, result.getInt("controlCalls"))
                assertEquals(++sequence, result.getLong("serverAcceptSequence"))
                assertEquals(Stage.values().toList(), protector.lastStages)
            }
            dial()
            val fds = settledFdCount()
            val packets = LiveCaptureStore.state.value.packetCount
            repeat(20) { dial() }
            SystemClock.sleep(500)
            assertTrue("Possible VPN recursion", LiveCaptureStore.state.value.packetCount - packets <= 16)
            assertTrue("Go/dup FD leak", settledFdCount() <= fds)
        } finally {
            context.startService(Intent(context, LiveCaptureVpnService::class.java).setAction(LiveCaptureVpnService.ACTION_STOP))
            waitUntil("VPN capture stop") { !LiveCaptureStore.state.value.isCapturing }
        }
        val stopped = LiveCaptureStore.state.value
        assertNull(stopped.error)
        val pcap = File(requireNotNull(stopped.outputPath)).readBytes()
        // Exactly the one positive-control SYN enters TUN. Go's 21 protected
        // sockets must be absent, even though excludeSelf=false and IPv6 routed.
        assertEquals("Protected socket entered TUN or positive control missing", 1, countTargetSyn(pcap, address.address, port))
    }

    @Suppress("DEPRECATION")
    private fun physicalNetwork(): NetworkSnapshot {
        val candidates = listOfNotNull(connectivity.activeNetwork) + connectivity.allNetworks
        val network = candidates.distinct().firstOrNull {
            connectivity.getNetworkCapabilities(it)?.hasTransport(NetworkCapabilities.TRANSPORT_VPN) == false
        } ?: error("A physical network is required")
        return NetworkSnapshot(network, 7)
    }

    private fun assertUnconnected(fd: Int) {
        ParcelFileDescriptor.fromFd(fd).use {
            try { Os.getpeername(it.fileDescriptor); fail("protect called after connect") }
            catch (error: ErrnoException) { assertEquals(OsConstants.ENOTCONN, error.errno) }
        }
    }

    private fun countTargetSyn(pcap: ByteArray, address: ByteArray, port: Int): Int {
        fun le(offset: Int) = (0..3).fold(0) { n, i -> n or ((pcap[offset+i].toInt() and 255) shl (8*i)) }
        fun u16(offset: Int) = ((pcap[offset].toInt() and 255) shl 8) or (pcap[offset+1].toInt() and 255)
        assertTrue(pcap.size >= 24)
        assertEquals(0xa1b2c3d4.toInt(), le(0))
        var offset = 24
        var count = 0
        while (offset + 16 <= pcap.size) {
            val size = le(offset + 8)
            val packet = offset + 16
            require(size >= 0 && packet + size <= pcap.size)
            if (size >= 40) {
                val version = (pcap[packet].toInt() ushr 4) and 15
                val tcp = when (version) { 4 -> packet + (pcap[packet].toInt() and 15) * 4; 6 -> packet + 40; else -> -1 }
                val destination = when (version) { 4 -> packet + 16; 6 -> packet + 24; else -> -1 }
                val protocol = when (version) { 4 -> pcap[packet+9].toInt(); 6 -> pcap[packet+6].toInt(); else -> -1 }
                if (protocol == 6 && tcp >= packet && tcp + 20 <= packet + size &&
                    address.size == (if (version == 4) 4 else 16) &&
                    pcap.copyOfRange(destination, destination + address.size).contentEquals(address) &&
                    u16(tcp+2) == port && (pcap[tcp+13].toInt() and 0x12) == 2) count++
            }
            offset = packet + size
        }
        assertEquals("Truncated PCAP tail", pcap.size, offset)
        return count
    }

    private fun settledFdCount() = (1..5).minOf {
        SystemClock.sleep(100)
        File("/proc/self/fd").list()?.size ?: error("Cannot inspect descriptors")
    }

    private fun waitUntil(message: String, predicate: () -> Boolean) {
        val end = SystemClock.elapsedRealtime() + 20_000
        while (!predicate() && SystemClock.elapsedRealtime() < end) SystemClock.sleep(100)
        assertTrue(message, predicate())
    }

    private fun success(text: String) = JSONObject(text).also {
        assertEquals(1, it.getInt("schemaVersion"))
        assertTrue(text, it.getBoolean("success"))
        assertTrue(it.isNull("errorCode"))
        assertTrue(it.isNull("error"))
    }
}
