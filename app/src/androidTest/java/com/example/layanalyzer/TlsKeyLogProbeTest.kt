package com.example.layanalyzer

import android.net.VpnService
import android.os.SystemClock
import android.system.ErrnoException
import android.system.Os
import android.system.OsConstants
import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.platform.app.InstrumentationRegistry
import org.json.JSONObject
import org.junit.Assert.*
import org.junit.Before
import org.junit.Test
import org.junit.runner.RunWith
import java.io.File

/** TLS-006 local lab. No skips; this does not claim Android TUN/PCAP decryption. */
@RunWith(AndroidJUnit4::class)
class TlsKeyLogProbeTest {
    @Before
    fun loadProbe() {
        assertTrue("Build the app and test APK with TLS probe ON", BuildConfig.TLS_PROBE_ENABLED)
        assertTrue(JSONObject(NativeEngine.loadTlsBridgeProbe(false, 1)).getBoolean("success"))
    }

    @Test fun tls12H1() = checkProtocol(0, 771, "http/1.1", 1)
    @Test fun tls13H1() = checkProtocol(1, 772, "http/1.1", 4)
    @Test fun tls13H2() = checkProtocol(2, 772, "h2", 4)

    @Test
    fun invalidRootNeverCompletesDownstream() {
        val buffers = NativeEngine.runTlsKeyLogProbe(2, true, callback())
        try {
            assertEquals(3, buffers.size)
            val result = JSONObject(buffers[0].toString(Charsets.UTF_8))
            assertFalse(result.getBoolean("success"))
            assertEquals("UPSTREAM_CERT_INVALID", result.getString("errorCode"))
            assertFalse(result.getBoolean("downstreamHandshake"))
            assertFalse(result.getBoolean("configReplaced"))
            assertEquals(0, buffers[1].size)
            assertEquals(0, result.getInt("bodyBytes"))
            assertCallbackReleased()
        } finally {
            buffers.forEach { it.fill(0) }
        }
    }

    @Test
    fun prepareFailureAndExceptionDoNotYieldDownstreamSecrets() {
        for (throws in listOf(false, true)) {
            val buffers = NativeEngine.runTlsKeyLogProbe(1, false) { _, _ ->
                if (throws) error("Synthetic callback exception must remain private")
                """{"schemaVersion":1,"success":false,"errorCode":"PROTECT_FAILED","error":"Synthetic failure"}"""
            }
            try {
                val result = JSONObject(buffers[0].toString(Charsets.UTF_8))
                assertFalse(result.getBoolean("success"))
                assertEquals(if (throws) "IO_ERROR" else "PROTECT_FAILED", result.getString("errorCode"))
                assertFalse(result.getBoolean("downstreamHandshake"))
                assertEquals(0, buffers[1].size)
                assertEquals(0, buffers[2].size)
                assertCallbackReleased()
            } finally {
                buffers.forEach { it.fill(0) }
            }
        }
    }

    private fun checkProtocol(protocol: Int, version: Int, alpn: String, lines: Int) {
        // Warm up Go/runtime HTTP2 machinery before comparing FD ownership.
        NativeEngine.runTlsKeyLogProbe(protocol, false, callback()).forEach { it.fill(0) }
        val baseline = settledFdCount()
        var prepareCalls = 0
        val buffers = NativeEngine.runTlsKeyLogProbe(protocol, false, callback { prepareCalls++ })
        try {
            assertEquals(3, buffers.size)
            val result = JSONObject(buffers[0].toString(Charsets.UTF_8))
            assertTrue(result.optString("errorCode"), result.getBoolean("success"))
            assertEquals(1, prepareCalls)
            assertEquals(1, result.getInt("schemaVersion"))
            assertTrue(result.isNull("errorCode"))
            assertTrue(result.isNull("error"))
            assertTrue(result.getBoolean("upstreamVerified"))
            assertTrue(result.getBoolean("configReplaced"))
            assertTrue(result.getBoolean("downstreamHandshake"))
            assertEquals(version, result.getInt("tlsVersion"))
            assertEquals(alpn, result.getString("alpn"))
            assertEquals(29, result.getInt("bodyBytes"))
            assertEquals("9b1ce3253f3312a2d0f896f307a944a2effe972d55ba1a33cc939feb6e6fd7c4", result.getString("bodySha256"))
            val a = verifyKeys(buffers[1], lines)
            val b = verifyKeys(buffers[2], lines)
            assertNotEquals(a, b)
            assertEquals(a, result.getString("downstreamClientRandom"))
            assertEquals(b, result.getString("upstreamClientRandom"))
            // Synthetic secrets stay in test-private noBackup storage, outside FileProvider.
            val context = InstrumentationRegistry.getInstrumentation().targetContext
            val directory = File(context.noBackupFilesDir, "tls-006/protocol-$protocol").apply { mkdirs() }
            File(directory, "result.json").writeBytes(buffers[0])
            File(directory, "tls-a.keys").writeBytes(buffers[1])
            File(directory, "tls-b.keys").writeBytes(buffers[2])
            assertCallbackReleased()
            assertTrue("FD count increased after joined probe", settledFdCount() <= baseline)
        } finally {
            buffers.forEach { it.fill(0) }
        }
    }

    private fun callback(onPrepare: () -> Unit = {}) = NativeEngine.TlsSocketProbeCallback { fd, generation ->
        assertEquals(0L, generation)
        // Go owns this fd. Assert it is still unconnected; never close or retain it.
        android.os.ParcelFileDescriptor.fromFd(fd).use { duplicate ->
            try {
                Os.getpeername(duplicate.fileDescriptor)
                fail("prepare must run before connect")
            } catch (error: ErrnoException) {
                assertEquals(OsConstants.ENOTCONN, error.errno)
            }
        }
        assertTrue(VpnService().protect(fd))
        onPrepare()
        """{"schemaVersion":1,"success":true,"errorCode":null,"error":null}"""
    }

    private fun verifyKeys(bytes: ByteArray, lineCount: Int): String {
        assertTrue(bytes.size <= 16384)
        val rows = bytes.toString(Charsets.US_ASCII).trim().lines().map { it.split(' ') }
        assertEquals(lineCount, rows.size)
        assertTrue(rows.all { it.size == 3 && it[1].matches(Regex("[0-9a-f]{64}")) })
        assertEquals(1, rows.map { it[1] }.toSet().size)
        assertEquals(lineCount, rows.map { it[0] }.toSet().size)
        return rows.first()[1]
    }

    private fun assertCallbackReleased() {
        val state = JSONObject(NativeEngine.getTlsBridgeProbeState())
        assertEquals(0, state.getInt("globalRefs"))
        assertEquals(0, state.getInt("attachedThreads"))
        assertEquals(state.getLong("callbacksStarted"), state.getLong("callbacksCompleted"))
    }

    // ART and the Go runtime close sockets asynchronously, so a single
    // instantaneous /proc/self/fd read races the teardown of the run just
    // measured. Compare settled minima, the same way TlsSocketProbeTest does.
    private fun settledFdCount(): Int = (1..5).minOf {
        SystemClock.sleep(100)
        requireNotNull(File("/proc/self/fd").list()).size
    }
}
