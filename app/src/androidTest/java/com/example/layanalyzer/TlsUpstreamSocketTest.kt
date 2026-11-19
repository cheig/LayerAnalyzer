package com.example.layanalyzer

import android.content.Context
import android.net.ConnectivityManager
import android.net.NetworkCapabilities
import android.os.SystemClock
import android.system.Os
import android.system.OsConstants
import androidx.test.core.app.ApplicationProvider
import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.platform.app.InstrumentationRegistry
import com.example.layanalyzer.capture.tls.UpstreamSocketProtector
import com.example.layanalyzer.capture.tls.UpstreamSocketProtector.NetworkSnapshot
import com.example.layanalyzer.capture.tls.UpstreamSocketProtector.Stage
import org.json.JSONObject
import org.junit.Assert.*
import org.junit.Test
import org.junit.runner.RunWith
import java.io.File
import java.io.IOException
import java.net.InetAddress
import java.net.ServerSocket
import java.net.UnknownHostException
import java.util.concurrent.atomic.AtomicReference

/**
 * TLS-203 production upstream path: the shared socket/DNS callbacks of C05.
 *
 * No Assume: a missing physical network or a missing fixture argument is an
 * unfulfilled gate, not a pass. Run on both ABIs with
 *
 * `-Pandroid.testInstrumentationRunnerArguments.tlsUpstreamHost=<name resolvable
 *   on the device's physical network>`
 *   (default fixture: the controlled LAS1 server used by TlsSocketProbeTest)
 *
 * This test intentionally drives no socket of its own. Android's public API
 * cannot turn a `FileDescriptor` back into the integer descriptor C05 carries,
 * and reflection into `java.io.FileDescriptor` is forbidden by design, so the
 * protect/bind-before-connect and no-recursion cases are only reachable with a
 * descriptor Go owns:
 *
 * - TLS-005's device test already asserts ENOTCONN after the same
 *   `prepareSocket` callback and exactly one target SYN in the capture under a
 *   self-capturing VPN (see evidence/TLS-005.md).
 * - `internal/uplink`'s host tests assert, against real loopback listeners,
 *   that every attempt is protected, that a rejected preparation never
 *   connects, and that each attempt gets its own descriptor.
 * - TLS-215/TLS-218 re-run that end to end with a production Go-owned socket.
 *
 * What remains here is everything that needs no descriptor: the resolution
 * contract, its validation, and the failure paths that reject before any
 * duplication. No engine is started and no production entry point is enabled.
 */
@RunWith(AndroidJUnit4::class)
class TlsUpstreamSocketTest {
    private val context = ApplicationProvider.getApplicationContext<Context>()
    private val connectivity = context.getSystemService(ConnectivityManager::class.java)
    private val arguments = InstrumentationRegistry.getArguments()
    private val generation = 7L

    @Test
    fun resolutionUsesOnlyTheSelectedNetwork() {
        val snapshot = physicalNetwork()
        val host = requireNotNull(arguments.getString("tlsUpstreamHost")) {
            "Required fixture argument: tlsUpstreamHost"
        }
        val protector = UpstreamSocketProtector({ snapshot }, noSocket())
        val resolved = success(protector.resolveHost(host, generation))
        val addresses = resolved.getJSONArray("addresses")
        assertTrue("no address for $host", addresses.length() > 0)
        val values = (0 until addresses.length()).map { addresses.getString(it) }
        values.forEach { assertLiteralAddress(it) }
        assertEquals("duplicate addresses returned", values.size, values.distinct().size)

        // Malformed input and a stale or missing network are rejected before any
        // lookup: the resolver below must never be reached.
        val untouchedResolver: (android.net.Network, String) -> Array<InetAddress>? = { _, _ ->
            throw AssertionError("input should have been rejected before resolving")
        }
        val untouched = UpstreamSocketProtector({ snapshot }, noSocket(), noBind(), untouchedResolver)
        failure(untouched.resolveHost(host, -1), "INVALID_ARGUMENT")
        failure(untouched.resolveHost("", generation), "INVALID_ARGUMENT")
        failure(untouched.resolveHost(".", generation), "INVALID_ARGUMENT")
        failure(untouched.resolveHost("example.test:443", generation), "INVALID_ARGUMENT")
        failure(untouched.resolveHost("exa mple.test", generation), "INVALID_ARGUMENT")
        failure(untouched.resolveHost("-leading.test", generation), "INVALID_ARGUMENT")
        failure(untouched.resolveHost("trailing-.test", generation), "INVALID_ARGUMENT")
        failure(untouched.resolveHost("example..test", generation), "INVALID_ARGUMENT")
        failure(untouched.resolveHost("a".repeat(254), generation), "INVALID_ARGUMENT")
        failure(untouched.resolveHost("a".repeat(64) + ".test", generation), "INVALID_ARGUMENT")
        val stale = UpstreamSocketProtector({ snapshot.copy(generation = generation + 1) }, noSocket())
        failure(stale.resolveHost(host, generation), "STALE_GENERATION")
        val lost = UpstreamSocketProtector({ null }, noSocket())
        failure(lost.resolveHost(host, generation), "NETWORK_CHANGED")
    }

    @Test
    fun resolutionNeverFallsBackToAnotherResolver() {
        val snapshot = physicalNetwork()
        val host = requireNotNull(arguments.getString("tlsUpstreamHost")) {
            "Required fixture argument: tlsUpstreamHost"
        }
        var asked = 0
        // The name does resolve on this device, but the captured network's
        // resolver reports no answer. A fallback to the process default resolver
        // would turn this into a success, so IO_ERROR proves there is none.
        val blocked = UpstreamSocketProtector({ snapshot }, noSocket(), noBind()) { _, _ ->
            asked++
            throw UnknownHostException("fixture-only")
        }
        val refused = failure(blocked.resolveHost(host, generation), "IO_ERROR")
        assertFalse("a failed resolution still offered addresses", refused.has("addresses"))
        assertEquals(1, asked)

        val empty = UpstreamSocketProtector({ snapshot }, noSocket(), noBind()) { _, _ -> emptyArray<InetAddress>() }
        failure(empty.resolveHost(host, generation), "IO_ERROR")

        // A lookup that outlives the captured network must not be used.
        val moving = AtomicReference<NetworkSnapshot?>(snapshot)
        val lostDuringLookup = UpstreamSocketProtector({ moving.get() }, noSocket(), noBind()) { _, _ ->
            moving.set(null)
            arrayOf(InetAddress.getByAddress(byteArrayOf(192.toByte(), 0, 2, 9)))
        }
        failure(lostDuringLookup.resolveHost(host, generation), "NETWORK_CHANGED")

        // A scoped IPv6 answer cannot be dialed through the ABI, so it is not
        // offered as a usable result.
        val scoped = UpstreamSocketProtector({ snapshot }, noSocket(), noBind()) { _, _ ->
            arrayOf(InetAddress.getByName("fe80::1%wlan0"))
        }
        failure(scoped.resolveHost(host, generation), "IO_ERROR")
    }

    @Test
    fun rejectedPreparationNeverBindsOrConnects() {
        val snapshot = physicalNetwork()
        ServerSocket(0, 8, InetAddress.getByName("127.0.0.1")).use { server ->
            server.soTimeout = 250
            // The descriptor never reaches Android: every case below is decided
            // before the callback would duplicate it, which is exactly the
            // property that stops a rejected attempt from connecting. The
            // bind-time failures that do need a real descriptor (a throwing bind,
            // a network lost while binding) are asserted by TlsSocketProbeTest,
            // which runs the same callback with a descriptor Go owns.
            val baseline = settledFdCount()
            repeat(10) {
                val rejected = UpstreamSocketProtector({ snapshot }, { false })
                failure(rejected.prepareSocket(DESCRIPTOR, generation), "PROTECT_FAILED")
                assertEquals(listOf(Stage.Validated), rejected.lastStages)

                failure(UpstreamSocketProtector({ snapshot.copy(generation = generation + 1) }, noSocket())
                    .prepareSocket(DESCRIPTOR, generation), "STALE_GENERATION")
                failure(UpstreamSocketProtector({ null }, noSocket())
                    .prepareSocket(DESCRIPTOR, generation), "NETWORK_CHANGED")
                failure(UpstreamSocketProtector({ snapshot }, noSocket())
                    .prepareSocket(DESCRIPTOR, -1), "INVALID_ARGUMENT")
                // Socket preparation never consults DNS.
                failure(UpstreamSocketProtector({ snapshot }, { false }, noBind()) { _, _ ->
                    throw AssertionError("socket preparation must not resolve")
                }.prepareSocket(DESCRIPTOR, generation), "PROTECT_FAILED")
            }
            assertTrue("FD count grew", settledFdCount() <= baseline)
            try {
                server.accept().use { fail("A rejected preparation reached connect") }
            } catch (_: IOException) { /* expected: zero accepted sockets */ }
        }
    }

    private fun noSocket(): (Int) -> Boolean = { fail("no socket expected"); false }
    private fun noBind(): (android.net.Network, java.io.FileDescriptor) -> Unit = { _, _ ->
        fail("no bind expected")
    }

    private fun physicalNetwork(): NetworkSnapshot {
        @Suppress("DEPRECATION")
        val candidates = listOfNotNull(connectivity.activeNetwork) + connectivity.allNetworks
        val network = candidates.distinct().firstOrNull {
            connectivity.getNetworkCapabilities(it)?.hasTransport(NetworkCapabilities.TRANSPORT_VPN) == false
        } ?: error("A physical network is required")
        return NetworkSnapshot(network, generation)
    }

    private fun assertLiteralAddress(value: String) {
        assertFalse("a scoped address cannot be dialed", value.contains('%'))
        val family = if (value.contains(':')) OsConstants.AF_INET6 else OsConstants.AF_INET
        try {
            Os.inet_pton(family, value)
        } catch (error: android.system.ErrnoException) {
            fail("resolver returned a non-literal address: ${error.errno}")
        }
    }
    private fun settledFdCount() = (1..5).minOf {
        SystemClock.sleep(100)
        File("/proc/self/fd").list()?.size ?: error("Cannot inspect descriptors")
    }

    private fun success(text: String) = JSONObject(text).also {
        assertEquals(1, it.getInt("schemaVersion"))
        assertTrue(text, it.getBoolean("success"))
        assertTrue(it.isNull("errorCode"))
        assertTrue(it.isNull("error"))
    }

    private fun failure(text: String, expected: String) = JSONObject(text).also {
        assertEquals(1, it.getInt("schemaVersion"))
        assertFalse(text, it.getBoolean("success"))
        assertEquals(expected, it.getString("errorCode"))
        assertFalse("TLS-203 callbacks must not leak platform text", it.isNull("error"))
    }

    private companion object {
        /** Any non-negative integer: no case here reaches the descriptor. */
        const val DESCRIPTOR = 42
    }
}
