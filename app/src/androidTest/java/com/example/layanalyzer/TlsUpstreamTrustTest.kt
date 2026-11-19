package com.example.layanalyzer

import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.platform.app.InstrumentationRegistry
import com.example.layanalyzer.capture.tls.AndroidUpstreamTrustVerifier
import com.example.layanalyzer.capture.tls.PlatformTrustUnavailableException
import com.example.layanalyzer.capture.tls.UpstreamChainVerifier
import android.net.http.X509TrustManagerExtensions
import org.json.JSONObject
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test
import org.junit.runner.RunWith
import java.security.KeyStore
import java.security.cert.CertificateException
import java.security.cert.CertificateFactory
import java.security.cert.X509Certificate
import javax.net.ssl.TrustManagerFactory
import javax.net.ssl.X509TrustManager

/**
 * TLS-204 device gate: the production upstream verifier driven against the
 * platform's real trust machinery - the device system trust store, and a
 * `X509TrustManagerExtensions` wrapping a fixture root - rather than against a
 * host stand-in.
 *
 * No Assume and no skip: a missing asset, a fixture that stopped verifying or a
 * platform that rejects a supported algorithm is a failure, not a pass. The
 * fixture root is never installed into the device trust store; it lives in an
 * in-memory KeyStore inside this test, which is the only place test-only roots
 * are allowed to be injected.
 *
 * This test doesn't run a TLS handshake of its own: it hands the verifier the
 * exact chain, algorithm and identity Go's VerifyConnection forwards
 * (TLS-209/TLS-215 own the byte transport). The Go half's real TLS1.2 and TLS1.3
 * handshakes are in `internal/tlsproxy`.
 */
@RunWith(AndroidJUnit4::class)
class TlsUpstreamTrustTest {
    private val assets = InstrumentationRegistry.getInstrumentation().context.assets
    private val manifest = JSONObject(String(asset("manifest.json")))
    private val identity = manifest.getString("identity")

    @Test
    fun systemTrustManagerRejectsAnUnknownFixtureRoot() {
        // The production default: the device trust store, wrapped for the
        // hostname-taking overload. A fresh fixture root is not in it, so every
        // committed leaf must be refused as a certificate verdict - not as an
        // unclassified error, and never as a success.
        val verifier = AndroidUpstreamTrustVerifier()
        for (case in cases()) {
            val leaf = certificate(asset(case.getString("leaf")))
            val response = verifier.verifyUpstream(arrayOf(leaf.encoded), case.getString("identity"),
                reportedAuthType(leaf), "TLSv1.3")
            failure(response, "UPSTREAM_CERT_INVALID")
            // The system trust store is not a per-call resource: repeated calls
            // answer identically.
            assertEquals(response, verifier.verifyUpstream(arrayOf(leaf.encoded), case.getString("identity"),
                reportedAuthType(leaf), "TLSv1.3"))
        }
    }

    @Test
    fun fixtureTrustRootVerifiesTheCommittedCases() {
        // Same production verifier, same production platform call, with the
        // fixture root as the only trust anchor. This is where the platform's
        // chain, validity, DNS SAN and IP SAN decisions are exercised for real.
        for (case in cases()) {
            val leaf = asset(case.getString("leaf"))
            val verifier = AndroidUpstreamTrustVerifier(fixtureTrust(case))
            for (version in listOf("TLSv1.2", "TLSv1.3")) {
                val response = verifier.verifyUpstream(arrayOf(leaf), case.getString("identity"),
                    reportedAuthType(certificate(leaf)), version)
                if (case.getString("expected") == "verified") success(response) else failure(response, "UPSTREAM_CERT_INVALID")
            }
        }
    }

    @Test
    fun thePlatformReceivesTheChainAlgorithmAndCanonicalIdentity() {
        val leaf = asset("leaf-valid-ec.der")
        var seenAuthType: String? = null
        var seenIdentity: String? = null
        var seenChain: Int? = null
        val recording = UpstreamChainVerifier { chain, authType, host ->
            seenChain = chain.size
            seenAuthType = authType
            seenIdentity = host
        }
        success(AndroidUpstreamTrustVerifier(recording).verifyUpstream(
            arrayOf(leaf, asset("root.der")), "UPSTREAM.Fixture.Test.", "ECDSA", "TLSv1.3"))
        assertEquals(2, seenChain)
        assertEquals("ECDSA", seenAuthType)
        assertEquals("UPSTREAM.Fixture.Test", seenIdentity)
    }

    @Test
    fun inputPolicyRejectsBeforeThePlatform() {
        fun rejects(case: String, chain: Array<ByteArray>, reference: String, authType: String, version: String, code: String) {
            val verifier = AndroidUpstreamTrustVerifier { _, _, _ -> throw AssertionError("$case reached the platform") }
            failure(verifier.verifyUpstream(chain, reference, authType, version), code)
        }
        val valid = arrayOf(asset("leaf-valid-ec.der"))
        rejects("empty chain", emptyArray(), identity, "ECDSA", "TLSv1.3", "INVALID_ARGUMENT")
        rejects("seventeen certificates", Array(17) { valid[0] }, identity, "ECDSA", "TLSv1.3", "INVALID_ARGUMENT")
        rejects("oversized certificate", arrayOf(ByteArray(65_537)), identity, "ECDSA", "TLSv1.3", "INVALID_ARGUMENT")
        rejects("malformed DER", arrayOf(byteArrayOf(0x30, 0x02, 0x00, 0x00)), identity, "ECDSA", "TLSv1.3", "INVALID_ARGUMENT")
        for (bad in listOf("", "*.fixture.test", "upstream.fixture.test:443", "upstream fixture.test",
            "[127.0.0.1]", "fe80::1%wlan0", "a".repeat(254), "café.fixture.test")) {
            rejects("identity $bad", valid, bad, "ECDSA", "TLSv1.3", "INVALID_ARGUMENT")
        }
        for (bad in listOf("", "TLSv1.0", "TLSv1.1", "SSLv3")) {
            rejects("version $bad", valid, identity, "ECDSA", bad, "UNSUPPORTED")
        }
        rejects("authType RSA for an EC leaf", valid, identity, "RSA", "TLSv1.3", "INVALID_ARGUMENT")
        rejects("authType ECDSA for an RSA leaf", arrayOf(asset("leaf-valid-rsa.der")), identity, "ECDSA", "TLSv1.3", "INVALID_ARGUMENT")
    }

    @Test
    fun platformFailuresAreMappedByType() {
        val chain = arrayOf(asset("leaf-valid-ec.der"))
        val diagnostic = "platform diagnostic: 10.0.0.1 certificate rejected"
        val cases = mapOf(
            UpstreamChainVerifier { _, _, _ -> throw PlatformTrustUnavailableException(diagnostic) } to "UNSUPPORTED",
            UpstreamChainVerifier { _, _, _ -> throw CertificateException(diagnostic) } to "UPSTREAM_CERT_INVALID",
            UpstreamChainVerifier { _, _, _ -> throw IllegalStateException(diagnostic) } to "IO_ERROR",
            UpstreamChainVerifier { _, _, _ -> throw java.io.IOException(diagnostic) } to "IO_ERROR"
        )
        for ((delegate, expected) in cases) {
            val response = AndroidUpstreamTrustVerifier(delegate).verifyUpstream(chain, identity, "ECDSA", "TLSv1.3")
            failure(response, expected)
            assertFalse("platform text leaked into the envelope", response.contains("10.0.0.1"))
        }
    }

    /**
     * Fixture trust source: the platform's `X509TrustManagerExtensions` over an
     * in-memory KeyStore holding the fixture root. Test-only roots are injected
     * here and never into the device trust store.
     */
    private fun fixtureTrust(case: JSONObject): UpstreamChainVerifier {
        val store = KeyStore.getInstance(KeyStore.getDefaultType())
        store.load(null, null)
        val roots = case.getJSONArray("trust")
        for (index in 0 until roots.length()) {
            store.setCertificateEntry("fixture-root-$index", certificate(asset(roots.getString(index))))
        }
        val factory = TrustManagerFactory.getInstance("X509")
        factory.init(store)
        val manager = factory.trustManagers.filterIsInstance<X509TrustManager>().singleOrNull()
            ?: throw AssertionError("the platform exposes no X509 trust manager")
        val extensions = try {
            X509TrustManagerExtensions(manager)
        } catch (error: IllegalArgumentException) {
            throw AssertionError("the platform cannot audit a fixture trust manager: ${error.message}")
        }
        return UpstreamChainVerifier { chain, authType, host ->
            // The hostname-taking overload: chain and identity in one call. The
            // hostname-less overload is never used here, exactly as in
            // production.
            extensions.checkServerTrusted(chain, authType, host)
        }
    }

    private fun cases(): List<JSONObject> = manifest.getJSONArray("cases").let { list ->
        (0 until list.length()).map { list.getJSONObject(it) }
    }

    private fun asset(name: String): ByteArray = assets.open("tls/upstream-trust/$name").use { it.readBytes() }

    private fun certificate(der: ByteArray): X509Certificate =
        CertificateFactory.getInstance("X.509").generateCertificate(der.inputStream()) as X509Certificate

    private fun reportedAuthType(leaf: X509Certificate): String = when (leaf.publicKey.algorithm) {
        "RSA" -> "RSA"
        "EC" -> "ECDSA"
        else -> throw AssertionError("unexpected fixture key algorithm ${leaf.publicKey.algorithm}")
    }

    private fun success(text: String) = JSONObject(text).also {
        assertEquals(1, it.getInt("schemaVersion"))
        assertTrue(text, it.getBoolean("success"))
        assertTrue(text, it.isNull("errorCode"))
        assertTrue(text, it.isNull("error"))
    }

    private fun failure(text: String, expected: String) = JSONObject(text).also {
        assertEquals(1, it.getInt("schemaVersion"))
        assertFalse(text, it.getBoolean("success"))
        assertEquals(expected, it.getString("errorCode"))
        assertFalse("failure must carry a fixed, non-platform message", it.isNull("error"))
    }
}
