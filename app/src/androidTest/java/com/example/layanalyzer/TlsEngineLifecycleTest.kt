package com.example.layanalyzer

import androidx.test.ext.junit.runners.AndroidJUnit4
import com.example.layanalyzer.capture.tls.TlsPlatformCallbacks
import org.json.JSONObject
import org.junit.Assert.*
import org.junit.FixMethodOrder
import org.junit.Test
import org.junit.runner.RunWith
import org.junit.runners.MethodSorters
import java.security.KeyPairGenerator
import java.security.Signature
import java.security.spec.ECGenParameterSpec
import java.util.concurrent.Callable
import java.util.concurrent.Executors
import java.util.concurrent.TimeUnit

/** Fresh process, both TLS ON and OFF. No probe, fixed root, or Assume/skips.
 * Actual RUNNING connections require later production assembly (TLS-213). */
@RunWith(AndroidJUnit4::class)
@FixMethodOrder(MethodSorters.NAME_ASCENDING)
class TlsEngineLifecycleTest {
    private val config = """{"schemaVersion":1,"captureId":"lifecycle-test","networkGeneration":1}"""
    private val callbacks = object : TlsPlatformCallbacks {
        override fun prepareSocket(fd: Int, networkGeneration: Long): String = unexpected()
        override fun resolveHost(host: String, networkGeneration: Long): String = unexpected()
        override fun verifyUpstream(chainDer: Array<ByteArray>, identity: String, authType: String, tlsVersion: String): String = unexpected()
        override fun offerSecret(captureId: String, connectionId: String, line: ByteArray): Boolean {
            unexpected(); return false
        }
        private fun unexpected(): String = throw AssertionError("Unassembled engine must never invoke callbacks")
    }

    @Test fun a_capabilityQueryDoesNotLoadGo() {
        assertTrue(NativeEngine.getVersion().isNotEmpty())
        val result = JSONObject(NativeEngine.getTlsProxyCapabilities())
        assertEquals(BuildConfig.TLS_ENABLED, result.getBoolean("buildEnabled"))
        assertFalse(result.getBoolean("libraryLoaded"))
        assertFalse(result.getBoolean("engineReady"))
        if (!BuildConfig.TLS_ENABLED) failure(result.toString(), "UNSUPPORTED")
    }

    @Test fun b_invalidInputsHaveNoHandleOrCallbacks() {
        failure(NativeEngine.startTlsProxy(config, byteArrayOf(1), byteArrayOf(1), callbacks),
            if (BuildConfig.TLS_ENABLED) "INVALID_ARGUMENT" else "UNSUPPORTED")
        failure(NativeEngine.startTlsProxy("{", byteArrayOf(1), byteArrayOf(1), callbacks),
            if (BuildConfig.TLS_ENABLED) "INVALID_ARGUMENT" else "UNSUPPORTED")
        failure(NativeEngine.pollTlsProxyEvents(0, 129),
            if (BuildConfig.TLS_ENABLED) "INVALID_ARGUMENT" else "UNSUPPORTED")
        noResources()
    }

    @Test fun c_validUnassembledStartFailsWithoutLeakingBuffersOrRefs() {
        val (certificate, key) = ephemeralTestCa()
        try {
            repeat(100) {
                failure(NativeEngine.startTlsProxy(config, certificate, key, callbacks),
                    if (BuildConfig.TLS_ENABLED) "NOT_READY" else "UNSUPPORTED")
            }
            noResources()
        } finally { key.fill(0) }
    }

    @Test fun d_staleHandleStopAndPollRaceIsBounded() {
        val pool = Executors.newFixedThreadPool(8)
        try {
            val tasks = (0 until 64).map { i -> Callable {
                val result = when (i % 3) {
                    0 -> NativeEngine.stopTlsProxy(Long.MAX_VALUE, 5_000)
                    1 -> NativeEngine.pollTlsProxyEvents(Long.MAX_VALUE, 128)
                    else -> NativeEngine.getTlsProxyStats(Long.MAX_VALUE)
                }
                failure(result, if (BuildConfig.TLS_ENABLED) "STALE_GENERATION" else "UNSUPPORTED")
            } }
            pool.invokeAll(tasks, 10, TimeUnit.SECONDS).forEach { it.get(1, TimeUnit.SECONDS) }
            noResources()
        } finally { pool.shutdownNow() }
    }

    private fun failure(raw: String, expected: String) {
        val value = JSONObject(raw)
        assertEquals(1, value.getInt("schemaVersion"))
        assertFalse(value.getBoolean("success"))
        assertEquals(expected, value.getString("errorCode"))
        assertFalse(value.has("engineHandle"))
        assertFalse(value.has("token"))
        assertFalse(value.has("port"))
    }

    private fun noResources() {
        val value = JSONObject(NativeEngine.getTlsProxyCapabilities())
        if (BuildConfig.TLS_ENABLED) {
            // TLS-213 installs the production factory at library load. Readiness
            // describes that factory; state NEW confirms no run was started.
            assertTrue(value.getBoolean("engineReady"))
            assertEquals("NEW", value.getString("state"))
            assertEquals(0L, value.getLong("globalRefs"))
            assertEquals(0L, value.getLong("attachedThreads"))
            assertEquals(0L, value.getLong("callbacksStarted"))
            assertEquals(0L, value.getLong("callbacksCompleted"))
            assertEquals(0L, value.getLong("buffersOutstanding"))
            assertEquals(value.getLong("buffersAllocated"), value.getLong("buffersFreed"))
        } else {
            assertFalse(value.getBoolean("engineReady"))
            assertFalse(value.getBoolean("libraryLoaded"))
        }
    }

    // Test-only DER encoding. JCA supplies all key generation/signing; no
    // runtime CA key or fixed probe root is bundled with the application.
    private fun ephemeralTestCa(): Pair<ByteArray, ByteArray> {
        val generator = KeyPairGenerator.getInstance("EC")
        generator.initialize(ECGenParameterSpec("secp256r1"))
        val key = generator.generateKeyPair()
        fun der(tag: Int, body: ByteArray): ByteArray {
            val length = when {
                body.size < 128 -> byteArrayOf(body.size.toByte())
                body.size < 256 -> byteArrayOf(0x81.toByte(), body.size.toByte())
                else -> byteArrayOf(0x82.toByte(), (body.size ushr 8).toByte(), body.size.toByte())
            }
            return byteArrayOf(tag.toByte()) + length + body
        }
        fun seq(vararg items: ByteArray) = der(0x30, items.fold(byteArrayOf()) { a, b -> a + b })
        val algorithm = seq(der(0x06, byteArrayOf(0x2a, 0x86.toByte(), 0x48, 0xce.toByte(), 0x3d, 0x04, 0x03, 0x02)))
        val name = seq(der(0x31, seq(der(0x06, byteArrayOf(0x55, 0x04, 0x03)), der(0x0c, "Ephemeral lifecycle test".toByteArray()))))
        val critical = der(0x01, byteArrayOf(0xff.toByte()))
        val constraints = seq(der(0x06, byteArrayOf(0x55, 0x1d, 0x13)), critical, der(0x04, seq(critical)))
        val usage = seq(der(0x06, byteArrayOf(0x55, 0x1d, 0x0f)), critical, der(0x04, der(0x03, byteArrayOf(2, 4))))
        val tbs = seq(der(0xa0, der(0x02, byteArrayOf(2))), der(0x02, byteArrayOf(1)), algorithm, name,
            seq(der(0x17, "200101000000Z".toByteArray()), der(0x17, "491231235959Z".toByteArray())),
            name, key.public.encoded, der(0xa3, seq(constraints, usage)))
        val signer = Signature.getInstance("SHA256withECDSA")
        signer.initSign(key.private)
        signer.update(tbs)
        return seq(tbs, algorithm, der(0x03, byteArrayOf(0) + signer.sign())) to key.private.encoded
    }
}
