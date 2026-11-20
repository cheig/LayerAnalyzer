// Copyright (c) 2026 cheig; GPL-3.0.
package com.example.layanalyzer

import androidx.test.ext.junit.runners.AndroidJUnit4
import com.example.layanalyzer.capture.tls.TlsGatewayChannel
import com.example.layanalyzer.capture.tls.TlsPlatformCallbacks
import com.example.layanalyzer.capture.tls.TlsRoutingPolicy
import com.example.layanalyzer.model.TlsCaptureSettings
import java.io.IOException
import java.net.InetAddress
import java.net.InetSocketAddress
import java.net.ServerSocket
import java.net.Socket
import java.net.SocketTimeoutException
import org.json.JSONObject
import org.junit.Assert.*
import org.junit.Before
import org.junit.Test
import org.junit.runner.RunWith
import java.util.concurrent.Callable
import java.util.concurrent.CyclicBarrier
import java.util.concurrent.Executors
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicInteger

/** Production JNI and bundled Wireshark, probe OFF. Barrier stress deliberately
 * bypasses the UI read gate to exercise native SessionLease/exclusive ownership.
 * This is analysis stress, not a VPN route/kill or platform trust test. */
@RunWith(AndroidJUnit4::class)
class TlsFailureRecoveryStressTest {
    @Before fun ready() {
        assertFalse("Release validation must not use P0 probes", BuildConfig.TLS_PROBE_ENABLED)
        assertTrue("Failure matrix must exercise the production Go JNI bridge", BuildConfig.TLS_ENABLED)
        NativeTestSupport.awaitApplicationEngine()
    }

    @Test fun tls12DetailsFilterFollowKeysCancelCloseAndReopen() = race("tls12-h1")
    @Test fun tls13H2DetailsFilterFollowKeysCancelCloseAndReopen() = race("tls13-h2")

    @Test fun jniCallbackExceptionStopsCleanlyAndNextEngineForwards() {
        val material = NativeEngine.generateTlsCaMaterial()
        val prepared = AtomicInteger()
        val worker = Executors.newSingleThreadExecutor()
        // Controlled on-device plain echo, no VPN or platform trust claim. The
        // first callback must fail before connect; the next run carries bytes.
        try {
            ServerSocket(0, 1, InetAddress.getByName("127.0.0.1")).use { origin ->
                origin.soTimeout = 2_000
                repeat(2) { round ->
                    val policy = TlsRoutingPolicy.freeze(TlsCaptureSettings(
                        enabled = true, candidatePorts = setOf(origin.localPort)))
                    val config = JSONObject().put("schemaVersion", 1).put("captureId", "tls403-$round")
                        .put("networkGeneration", 1).put("settings", JSONObject(policy.encode())).toString()
                    val callbacks = object : TlsPlatformCallbacks {
                        override fun prepareSocket(fd: Int, networkGeneration: Long): String {
                            prepared.incrementAndGet()
                            if (round == 0) throw IllegalStateException("injected private callback detail")
                            return JSONObject().put("schemaVersion", 1).put("success", true)
                                .put("errorCode", JSONObject.NULL).put("error", JSONObject.NULL).toString()
                        }
                        override fun resolveHost(host: String, networkGeneration: Long): String = error("numeric destination only")
                        override fun verifyUpstream(chainDer: Array<ByteArray>, identity: String,
                                                    authType: String, tlsVersion: String): String = error("plain echo only")
                        override fun offerSecret(captureId: String, connectionId: String, line: ByteArray): Boolean {
                            line.fill(0)
                            error("plain echo cannot produce secrets")
                        }
                    }
                    val started = success(NativeEngine.startTlsProxy(config, material[0], material[1], callbacks))
                    val handle = started.getLong("engineHandle")
                    val port = started.getInt("port")
                    try {
                        val token = NativeEngine.getTlsProxyToken(handle)
                        val channel = try {
                            TlsGatewayChannel(port, token, "tls403-$round", 1, policy, {})
                        } finally { token.fill(0) }
                        try {
                            if (round == 0) {
                                try {
                                    channel.withNioConnection("127.0.0.1", origin.localPort) { fail("throwing callback must refuse READY") }
                                    fail("Expected IO_ERROR")
                                } catch (error: NioSocksRefusal) {
                                    assertEquals(4, error.reply)
                                    assertFalse(error.message.orEmpty().contains("private callback detail"))
                                }
                                origin.soTimeout = 250
                                try { origin.accept().use { fail("failed preparation connected upstream") } }
                                catch (_: SocketTimeoutException) { }
                                origin.soTimeout = 2_000
                            } else {
                                val echo = worker.submit {
                                    origin.accept().use { peer ->
                                        peer.soTimeout = 2_000
                                        val bytes = ByteArray(8)
                                        java.io.DataInputStream(peer.getInputStream()).readFully(bytes)
                                        peer.getOutputStream().write(bytes)
                                    }
                                }
                                channel.withNioConnection("127.0.0.1", origin.localPort) { client ->
                                    client.soTimeout = 2_000
                                    val expected = "tls403ok".toByteArray()
                                    client.getOutputStream().write(expected)
                                    val actual = ByteArray(expected.size)
                                    java.io.DataInputStream(client.getInputStream()).readFully(actual)
                                    assertArrayEquals(expected, actual)
                                }
                                echo.get(5, TimeUnit.SECONDS)
                            }
                        } finally { channel.close() }
                    } finally {
                        repeat(2) { success(NativeEngine.stopTlsProxy(handle, 5_000)) }
                    }
                    try {
                        Socket().use { it.connect(InetSocketAddress("127.0.0.1", port), 500) }
                        fail("stopped gateway still listens")
                    } catch (_: IOException) { }
                    val resources = success(NativeEngine.getTlsProxyCapabilities())
                    assertEquals(0L, resources.getLong("globalRefs"))
                    assertEquals(0L, resources.getLong("attachedThreads"))
                    assertEquals(resources.getLong("callbacksStarted"), resources.getLong("callbacksCompleted"))
                    assertEquals(0L, resources.getLong("buffersOutstanding"))
                    assertEquals(resources.getLong("buffersAllocated"), resources.getLong("buffersFreed"))
                }
                assertEquals(2, prepared.get())
            }
        } finally {
            material.forEach { it.fill(0) }
            worker.shutdownNow()
            assertTrue(worker.awaitTermination(5, TimeUnit.SECONDS))
        }
    }

    private fun race(id: String) = TlsPassiveFixture(id).use { fixture ->
        val pool = Executors.newFixedThreadPool(6) { task ->
            Thread(task, "tls403-native-race").apply { isDaemon = true }
        }
        try {
            repeat(20) { round ->
                val handle = fixture.open()
                try {
                    val generation = success(NativeEngine.configureTlsSecrets(handle, fixture.file("keylog").path, 1))
                        .getLong("dissectionGeneration")
                    fixture.assertBody(handle, true)
                    val detail = success(NativeEngine.getPacketDetails(handle, 0))
                    val snapshot = detail.getString("snapshotId")
                    val start = CyclicBarrier(6)
                    val tasks = listOf<() -> Unit>(
                        {
                            repeat(16) {
                                val tree = JSONObject(NativeEngine.getPacketDetails(handle, 0))
                                // Legacy detail API returns {} after close.
                                if (tree.length() > 0) {
                                    assertTrue(tree.getBoolean("success"))
                                    assertEquals(1L, tree.getLong("frameNumber"))
                                    assertTrue(tree.getLong("dissectionGeneration") >= generation)
                                }
                            }
                        },
                        {
                            val result = JSONObject(NativeEngine.applyDisplayFilter(handle, "tcp"))
                            if (!result.getBoolean("success")) {
                                assertTrue(result.getString("error") in
                                    setOf("Operation cancelled.", "No capture is open."))
                            }
                        },
                        { checked(NativeEngine.followTlsStream(handle, 0, generation, 1024 * 1024)) },
                        {
                            checked(NativeEngine.configureTlsSecrets(handle, null, 2))
                            checked(NativeEngine.configureTlsSecrets(handle, fixture.file("keylog").path, 3))
                        },
                        {
                            repeat(16) {
                                val result = checked(NativeEngine.readPacketDataSource(
                                    handle, snapshot, "raw", 0, 1, generation))
                                if (result.getBoolean("success")) {
                                    assertEquals(snapshot, result.getString("snapshotId"))
                                    assertEquals(generation, result.getLong("dissectionGeneration"))
                                    assertEquals(1, result.getInt("length"))
                                }
                            }
                        },
                        {
                            NativeEngine.cancelLongRunningOperations()
                            NativeEngine.closeFile(handle)
                        }
                    ).map { operation -> Callable {
                        start.await(5, TimeUnit.SECONDS)
                        operation()
                    } }
                    val results = pool.invokeAll(tasks, 20, TimeUnit.SECONDS)
                    results.forEachIndexed { index, result ->
                        assertFalse("round=$round worker=$index exceeded 20s; possible lease/exclusive deadlock", result.isCancelled)
                        result.get(1, TimeUnit.SECONDS)
                    }
                    // Results that completed before close may be valid values;
                    // their source IDs must be unusable once close has returned.
                    val stale = checked(NativeEngine.getPacketDataSources(handle, snapshot, generation))
                    assertFalse(stale.getBoolean("success"))
                    assertEquals("NOT_READY", stale.getString("errorCode"))
                } finally {
                    NativeEngine.closeFile(handle)
                }
                // A fresh analysis must open without inherited keys, then decrypt
                // the independent Golden after explicit reconfiguration.
                val reopened = fixture.open()
                try {
                    fixture.assertBody(reopened, false)
                    success(NativeEngine.configureTlsSecrets(reopened, fixture.file("keylog").path, 1))
                    fixture.assertBody(reopened, true)
                } finally { fixture.closeCapture(reopened) }
            }
        } finally {
            pool.shutdownNow()
            assertTrue("native workers survived cancellation", pool.awaitTermination(5, TimeUnit.SECONDS))
        }
    }

    private fun checked(raw: String): JSONObject = JSONObject(raw).also {
        assertEquals(1, it.getInt("schemaVersion"))
        if (!it.getBoolean("success")) {
            assertTrue("unexpected native failure: ${it.optString("errorCode")}",
                it.getString("errorCode") in setOf("NOT_READY", "STALE_GENERATION", "CANCELLED"))
            assertFalse(it.has("bytesBase64"))
            it.optJSONArray("records")?.let { records -> assertEquals(0, records.length()) }
        }
    }

    private fun success(raw: String): JSONObject = checked(raw).also { assertTrue(it.getBoolean("success")) }
}
