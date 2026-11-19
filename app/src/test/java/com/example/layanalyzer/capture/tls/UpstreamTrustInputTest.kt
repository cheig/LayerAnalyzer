package com.example.layanalyzer.capture.tls

import org.json.JSONObject
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test
import java.io.File
import java.math.BigInteger
import java.net.InetAddress
import java.security.GeneralSecurityException
import java.security.MessageDigest
import java.security.Principal
import java.security.PublicKey
import java.security.cert.CertPathValidator
import java.security.cert.CertificateException
import java.security.cert.CertificateFactory
import java.security.cert.CertificateParsingException
import java.security.cert.PKIXParameters
import java.security.cert.TrustAnchor
import java.security.cert.X509Certificate
import java.util.Date

/**
 * TLS-204 host gate: the input policy, the delegation contract and the error
 * mapping of the production upstream verifier, plus a real cryptographic check
 * of the committed fixtures.
 *
 * The fixture delegate below is the "test-only extra roots" implementation the
 * card allows: a host PKIX trust manager built from the fixture root, and an
 * RFC 2818 name matcher. It is not the production path - the production path
 * uses the device's own trust store through X509TrustManagerExtensions and is
 * exercised by `TlsUpstreamTrustTest` on a device. Nothing here fakes a
 * platform decision: the fixture delegate really validates signatures, validity
 * windows and names, and the production verifier is what decides the code.
 */
class UpstreamTrustInputTest {
    private val directory = fixtureDirectory()
    private val manifest = JSONObject(File(directory, "manifest.json").readText())
    private val identity = manifest.getString("identity")
    private val ipIdentity = manifest.getString("ipIdentity")

    @Test
    fun supportedVersionAndAlgorithmMatrixIsPinned() {
        // The matrix the evidence records. Both versions go through the same
        // mandatory callback, and a version outside it is never intercepted.
        assertEquals(setOf("TLSv1.2", "TLSv1.3"), UpstreamTrustInput.supportedVersions)
        assertEquals(16, UpstreamTrustInput.MAX_CERTIFICATES)
        assertEquals(65_536, UpstreamTrustInput.MAX_CERTIFICATE_BYTES)
        assertEquals(253, UpstreamTrustInput.MAX_IDENTITY_LENGTH)
        assertEquals("ECDSA", UpstreamTrustInput.authType(leaf("leaf-valid-ec.der")))
        assertEquals("RSA", UpstreamTrustInput.authType(leaf("leaf-valid-rsa.der")))
        // The name the Go half reports is derived from the same leaf, so the two
        // halves must agree on every spelling seen on the wire.
        assertEquals("RSA", reportedAuthType(leaf("leaf-valid-rsa.der")))
        assertEquals("ECDSA", reportedAuthType(leaf("leaf-valid-ec.der")))
    }

    @Test
    fun committedFixtureManifestMatchesEveryFile() {
        assertFalse("fixture private keys must never be committed", manifest.getBoolean("privateKeysCommitted"))
        assertTrue(manifest.getInt("schemaVersion") == 1)
        val certificates = manifest.getJSONArray("certificates")
        assertTrue("no fixture certificate described", certificates.length() > 0)
        for (index in 0 until certificates.length()) {
            val entry = certificates.getJSONObject(index)
            val file = File(directory, entry.getString("file"))
            assertTrue("missing fixture ${entry.getString("file")}", file.isFile)
            assertEquals(entry.getString("file"), entry.getString("sha256"), sha256(file))
        }
        // The cases the two platform tests replay must cover every acceptance
        // item: a verified chain, a name mismatch, an expired leaf and a chain
        // anchored in a root that is not trusted.
        val expectations = manifest.getJSONArray("cases").let { cases ->
            (0 until cases.length()).map { cases.getJSONObject(it).getString("expected") }
        }
        assertTrue(expectations.contains("verified"))
        assertTrue(expectations.contains("name-mismatch"))
        assertTrue(expectations.contains("expired"))
        assertTrue(expectations.contains("unknown-ca"))
    }

    @Test
    fun verifiedFixtureCasesSucceedWithTheFixtureRoot() {
        var verified = 0
        for (case in cases()) {
            if (case.getString("expected") != "verified") continue
            val chain = arrayOf(der(case.getString("leaf")))
            val verifier = AndroidUpstreamTrustVerifier(fixtureVerifier(case))
            success(verifier.verifyUpstream(chain, case.getString("identity"), reportedAuthType(certificateOf(chain[0])), "TLSv1.3"))
            success(verifier.verifyUpstream(chain, case.getString("identity"), reportedAuthType(certificateOf(chain[0])), "TLSv1.2"))
            verified++
        }
        assertTrue("no verified fixture case ran", verified >= 3)
    }

    @Test
    fun rejectedFixtureCasesFailAsCertificateRejections() {
        var rejected = 0
        for (case in cases()) {
            if (case.getString("expected") == "verified") continue
            val chain = arrayOf(der(case.getString("leaf")))
            val verifier = AndroidUpstreamTrustVerifier(fixtureVerifier(case))
            // An expired or untrusted chain is a certificate verdict, never a
            // silent pass and never a generic platform error.
            failure(verifier.verifyUpstream(chain, case.getString("identity"), reportedAuthType(certificateOf(chain[0])), "TLSv1.3"),
                "UPSTREAM_CERT_INVALID")
            rejected++
        }
        assertTrue("no rejected fixture case ran", rejected >= 4)
    }

    @Test
    fun theRootDoesNotHaveToAppearInThePeerChain() {
        // Go forwards cs.PeerCertificates, which normally stops at the last
        // intermediate. Both forms must verify against the same root.
        val verifier = AndroidUpstreamTrustVerifier(fixtureVerifier(arrayOf(der("root.der"))))
        val leafOnly = arrayOf(der("leaf-valid-ec.der"))
        val withRoot = arrayOf(der("leaf-valid-ec.der"), der("root.der"))
        success(verifier.verifyUpstream(leafOnly, identity, "ECDSA", "TLSv1.3"))
        success(verifier.verifyUpstream(withRoot, identity, "ECDSA", "TLSv1.3"))
        // The decoy root anchors nothing, so the same leaf is rejected.
        val decoy = AndroidUpstreamTrustVerifier(fixtureVerifier(arrayOf(der("other-root.der"))))
        failure(decoy.verifyUpstream(leafOnly, identity, "ECDSA", "TLSv1.3"), "UPSTREAM_CERT_INVALID")
    }

    @Test
    fun thePlatformSeesTheExactChainAlgorithmAndCanonicalIdentity() {
        var seenChain: Array<X509Certificate>? = null
        var seenAuthType: String? = null
        var seenIdentity: String? = null
        val verifier = AndroidUpstreamTrustVerifier { chain, authType, host ->
            seenChain = chain
            seenAuthType = authType
            seenIdentity = host
        }
        success(verifier.verifyUpstream(
            arrayOf(der("leaf-valid-ec.der"), der("root.der")), "Upstream.Fixture.Test.", "ECDSA", "TLSv1.2"))
        assertEquals("the hostname-taking platform overload must receive the leaf-first chain",
            2, seenChain?.size)
        assertEquals("ECDSA", seenAuthType)
        // One trailing dot removed, case preserved: no other rewrite.
        assertEquals("Upstream.Fixture.Test", seenIdentity)
        // "EC" is the other JSSE spelling of the same leaf algorithm, so it is a
        // synonym and not a disagreement; the platform still receives "ECDSA".
        seenAuthType = null
        success(verifier.verifyUpstream(arrayOf(der("leaf-valid-ec.der")), identity, "EC", "TLSv1.3"))
        assertEquals("ECDSA", seenAuthType)
    }

    @Test
    fun invalidInputNeverReachesThePlatform() {
        val valid = arrayOf(der("leaf-valid-ec.der"))
        val rsa = arrayOf(der("leaf-valid-rsa.der"))

        rejects("empty chain", emptyArray(), identity, "ECDSA", "TLSv1.3", "INVALID_ARGUMENT")
        rejects("seventeen certificates", Array(17) { valid[0] }, identity, "ECDSA", "TLSv1.3", "INVALID_ARGUMENT")
        rejects("oversized certificate", arrayOf(ByteArray(65_537)), identity, "ECDSA", "TLSv1.3", "INVALID_ARGUMENT")
        rejects("malformed DER", arrayOf(byteArrayOf(0x30, 0x02, 0x00, 0x00)), identity, "ECDSA", "TLSv1.3", "INVALID_ARGUMENT")
        for (bad in listOf("", ".", "..", "*.fixture.test", "upstream.fixture.test:443", "upstream fixture.test",
            "[127.0.0.1]", "[2001:db8::1]", "fe80::1%wlan0", "-leading.fixture.test", "trailing-.fixture.test",
            "empty..fixture.test", "a".repeat(254), "a".repeat(64) + ".fixture.test", "café.fixture.test")) {
            rejects("identity $bad", valid, bad, "ECDSA", "TLSv1.3", "INVALID_ARGUMENT")
        }
        for (bad in listOf("", "TLSv1.0", "TLSv1.1", "SSLv3", "TLSv1.2 ", "tlsv1.3")) {
            rejects("version $bad", valid, identity, "ECDSA", bad, "UNSUPPORTED")
        }
        // A reported algorithm that the leaf does not have means the two halves
        // are looking at different chains.
        for (bad in listOf("", "banana", "RSA", "DSA", "EDDSA")) {
            rejects("authType $bad for an EC leaf", valid, identity, bad, "TLSv1.3", "INVALID_ARGUMENT")
        }
        for (bad in listOf("", "banana", "ECDSA", "DSA", "EDDSA")) {
            rejects("authType $bad for an RSA leaf", rsa, identity, bad, "TLSv1.3", "INVALID_ARGUMENT")
        }
    }

    /**
     * Every rejection below must be decided before the platform is asked: the
     * delegate fails the test if it is entered at all, and the message names the
     * input that got through.
     */
    private fun rejects(
        case: String,
        chain: Array<ByteArray>,
        reference: String,
        authType: String,
        version: String,
        expected: String
    ) {
        val verifier = AndroidUpstreamTrustVerifier { _, _, _ ->
            throw AssertionError("$case reached the platform")
        }
        failure(verifier.verifyUpstream(chain, reference, authType, version), expected)
    }

    @Test
    fun platformFailuresMapToFixedCodesAndHideTheirText() {
        val chain = arrayOf(der("leaf-valid-ec.der"))
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
            assertFalse("platform text leaked into the envelope", response.contains("diagnostic"))
        }
        success(AndroidUpstreamTrustVerifier { _, _, _ -> }.verifyUpstream(chain, identity, "ECDSA", "TLSv1.3"))
    }

    @Test
    fun referenceIdentityPolicyMatchesTheGoHalf() {
        for (accepted in listOf("upstream.fixture.test", "UPSTREAM.FIXTURE.TEST", "upstream.fixture.test.",
            "127.0.0.1", "2001:db8::1", "a-b.fixture.test", "a_b.fixture.test", "1.2.3.4")) {
            assertEquals(accepted, accepted.removeSuffix("."), UpstreamTrustInput.identity(accepted))
        }
        for (rejected in listOf("", ".", "..", "*.fixture.test", "upstream.fixture.test:443", "upstream fixture.test",
            "[2001:db8::1]", "fe80::1%wlan0", "-a.test", "a-.test", "a..b",
            "a".repeat(254), "a".repeat(64) + ".test", "a\u0000.test", "a\u007f.test", "é.test")) {
            assertNull("identity $rejected must be rejected", UpstreamTrustInput.identity(rejected))
        }
        // A dotted quad that is not a valid IPv4 literal is still a syntactically
        // valid DNS name, on both halves, so it is not rejected here.
        assertEquals("1.2.3.256", UpstreamTrustInput.identity("1.2.3.256"))
    }

    @Test
    fun theNameCheckRejectsAMismatchBeforeThePlatformIsAsked() {
        // The device gate's failure: the platform's hostname-taking overload
        // accepts a leaf whose SANs do not prove the reference identity. The
        // production verifier must reach the same verdict on its own, before the
        // delegate is consulted, for both a DNS and an IP reference identity.
        for (reference in listOf(identity, ipIdentity)) {
            var reached = false
            val wrong = AndroidUpstreamTrustVerifier { _, _, _ -> reached = true }
            failure(wrong.verifyUpstream(arrayOf(der("leaf-wrong-name.der")), reference,
                reportedAuthType(leaf("leaf-wrong-name.der")), "TLSv1.3"), "UPSTREAM_CERT_INVALID")
            assertFalse("the name mismatch for $reference must be decided before the platform", reached)

            var proven = false
            val valid = AndroidUpstreamTrustVerifier { _, _, _ -> proven = true }
            success(valid.verifyUpstream(arrayOf(der("leaf-valid-ec.der")), reference, "ECDSA", "TLSv1.3"))
            assertTrue("a proven identity for $reference must still reach the platform", proven)
        }
    }

    @Test
    fun nameMatcherCoversRfc6125DnsAndIpBoundaries() {
        // DNS: case-insensitive exact match, and the trailing dot is already
        // removed by identity() before the matcher runs.
        assertTrue(UpstreamNameVerifier.matchesAlternatives("Upstream.Fixture.Test", dns("upstream.fixture.test")))
        assertTrue(UpstreamNameVerifier.matchesAlternatives("upstream.fixture.test", dns("UPSTREAM.FIXTURE.TEST")))
        assertEquals("upstream.fixture.test", UpstreamTrustInput.identity("upstream.fixture.test."))
        assertTrue(UpstreamNameVerifier.matchesAlternatives(
            UpstreamTrustInput.identity("upstream.fixture.test.")!!, dns("upstream.fixture.test")))

        // A wildcard covers exactly one label and never the bare name.
        assertTrue(UpstreamNameVerifier.matchesAlternatives("x.a.test", dns("*.a.test")))
        assertFalse(UpstreamNameVerifier.matchesAlternatives("a.test", dns("*.a.test")))
        assertFalse(UpstreamNameVerifier.matchesAlternatives("x.y.a.test", dns("*.a.test")))
        assertTrue(UpstreamNameVerifier.matchesAlternatives("x.a.test", dns("*.A.TEST")))

        // IP: compared by address bytes, so every textual form of the same
        // address matches and a different address never does.
        assertTrue(UpstreamNameVerifier.matchesAlternatives("127.0.0.1", ip("127.0.0.1")))
        assertTrue(UpstreamNameVerifier.matchesAlternatives("127.0.0.1", ip(byteArrayOf(127, 0, 0, 1))))
        assertTrue(UpstreamNameVerifier.matchesAlternatives("2001:db8::1", ip("2001:0db8:0:0:0:0:0:1")))
        assertTrue(UpstreamNameVerifier.matchesAlternatives("::1", ip(InetAddress.getByName("::1").address)))
        assertFalse(UpstreamNameVerifier.matchesAlternatives("127.0.0.1", ip("127.0.0.2")))
        assertFalse(UpstreamNameVerifier.matchesAlternatives("2001:db8::1", ip("2001:db8::2")))

        // The families never cross: an IP identity never consults DNS SANs and a
        // DNS identity never consults IP SANs.
        assertFalse(UpstreamNameVerifier.matchesAlternatives("127.0.0.1", dns("127.0.0.1")))
        assertFalse(UpstreamNameVerifier.matchesAlternatives("upstream.fixture.test", ip("127.0.0.1")))
        assertFalse(UpstreamNameVerifier.matchesAlternatives("upstream.fixture.test", dns("other.fixture.test")))

        // Fail closed: no SAN, an empty SAN set, and an unparsable SAN extension.
        assertFalse(UpstreamNameVerifier.matchesAlternatives("upstream.fixture.test", null))
        assertFalse(UpstreamNameVerifier.matchesAlternatives("upstream.fixture.test", emptyList()))
        assertFalse(UpstreamNameVerifier.matches("upstream.fixture.test", leaf("root.der")))
        assertFalse(UpstreamNameVerifier.matches("upstream.fixture.test", UnparsableSanLeaf()))
    }

    private fun dns(vararg names: String): Collection<List<*>> =
        names.map { listOf(UpstreamNameVerifier.DNS_NAME, it) }

    private fun ip(vararg values: Any): Collection<List<*>> =
        values.map { listOf(UpstreamNameVerifier.IP_ADDRESS, it) }

    /**
     * A leaf whose SAN extension cannot be parsed. The verifier must fail closed
     * instead of letting a parsing failure escape as an unrelated platform error.
     */
    private class UnparsableSanLeaf : X509Certificate() {
        override fun getSubjectAlternativeNames(): Collection<List<*>> =
            throw CertificateParsingException("synthetic malformed SAN")

        override fun checkValidity() = throw UnsupportedOperationException()
        override fun checkValidity(date: Date) = throw UnsupportedOperationException()
        override fun getVersion(): Int = throw UnsupportedOperationException()
        override fun getSerialNumber(): BigInteger = throw UnsupportedOperationException()
        override fun getIssuerDN(): Principal = throw UnsupportedOperationException()
        override fun getSubjectDN(): Principal = throw UnsupportedOperationException()
        override fun getNotBefore(): Date = throw UnsupportedOperationException()
        override fun getNotAfter(): Date = throw UnsupportedOperationException()
        override fun getTBSCertificate(): ByteArray = throw UnsupportedOperationException()
        override fun getSignature(): ByteArray = throw UnsupportedOperationException()
        override fun getSigAlgName(): String = throw UnsupportedOperationException()
        override fun getSigAlgOID(): String = throw UnsupportedOperationException()
        override fun getSigAlgParams(): ByteArray? = throw UnsupportedOperationException()
        override fun getIssuerUniqueID(): BooleanArray? = throw UnsupportedOperationException()
        override fun getSubjectUniqueID(): BooleanArray? = throw UnsupportedOperationException()
        override fun getKeyUsage(): BooleanArray? = throw UnsupportedOperationException()
        override fun getBasicConstraints(): Int = throw UnsupportedOperationException()
        override fun hasUnsupportedCriticalExtension(): Boolean = throw UnsupportedOperationException()
        override fun getCriticalExtensionOIDs(): Set<String>? = throw UnsupportedOperationException()
        override fun getNonCriticalExtensionOIDs(): Set<String>? = throw UnsupportedOperationException()
        override fun getExtensionValue(oid: String): ByteArray? = throw UnsupportedOperationException()
        override fun getEncoded(): ByteArray = throw UnsupportedOperationException()
        override fun verify(key: PublicKey) = throw UnsupportedOperationException()
        override fun verify(key: PublicKey, sigProvider: String) = throw UnsupportedOperationException()
        override fun getPublicKey(): PublicKey = throw UnsupportedOperationException()
        override fun toString(): String = "UnparsableSanLeaf"
    }

    private fun cases(): List<JSONObject> = manifest.getJSONArray("cases").let { list ->
        (0 until list.length()).map { list.getJSONObject(it) }
    }

    private fun leaf(name: String): X509Certificate = certificateOf(der(name))

    private fun certificateOf(der: ByteArray): X509Certificate =
        requireNotNull(UpstreamTrustInput.certificates(arrayOf(der))) { "committed fixture is not a certificate" }[0]

    private fun der(name: String): ByteArray = File(directory, name).readBytes()

    /** The authType the Go half reports for this leaf, derived independently here. */
    private fun reportedAuthType(leaf: X509Certificate): String = when (leaf.publicKey.algorithm) {
        "RSA" -> "RSA"
        "EC" -> "ECDSA"
        else -> error("unexpected fixture key algorithm ${leaf.publicKey.algorithm}")
    }

    /**
     * Fixture delegate: real host PKIX validation against the roots named by the
     * case, plus an RFC 2818 name/IP check. Test-only roots are injected here and
     * nowhere else; production uses the device trust store.
     *
     * Validation goes through `CertPathValidator` rather than through
     * `X509TrustManager.checkServerTrusted(chain, authType)`, because the host
     * JVM's SunJSSE rejects the JSSE authType names ("ECDSA", "EC") that Android
     * accepts, so its authType handling says nothing about the platform's. The
     * path validation itself is real: signatures, validity windows, basic
     * constraints and the issuer DN of every certificate are checked
     * cryptographically. The leaf's serverAuth EKU is checked explicitly, as
     * JSSE would.
     */
    private fun fixtureVerifier(case: JSONObject): UpstreamChainVerifier {
        val roots = case.getJSONArray("trust").let { list -> (0 until list.length()).map { der(list.getString(it)) } }
        return fixtureVerifier(roots.toTypedArray())
    }

    private fun fixtureVerifier(roots: Array<ByteArray>): UpstreamChainVerifier {
        val anchors = roots.map { TrustAnchor(certificateOf(it), null) }.toSet()
        return UpstreamChainVerifier { chain, _, hostname ->
            try {
                val path = CertificateFactory.getInstance("X.509").generateCertPath(chain.toList())
                val parameters = PKIXParameters(anchors).apply { isRevocationEnabled = false }
                CertPathValidator.getInstance("PKIX").validate(path, parameters)
            } catch (error: GeneralSecurityException) {
                // A path that does not build or validate is a certificate
                // rejection, the same verdict the platform reports.
                throw CertificateException(error.message ?: "fixture path rejected")
            }
            if (!chain[0].extendedKeyUsage.orEmpty().contains(SERVER_AUTH)) {
                throw CertificateException("fixture leaf is not a server certificate")
            }
            if (!nameMatches(hostname, chain[0])) {
                throw CertificateException("fixture reference identity mismatch")
            }
        }
    }

    private fun nameMatches(identity: String, leaf: X509Certificate): Boolean {
        val alternatives = try {
            leaf.subjectAlternativeNames
        } catch (_: CertificateParsingException) {
            null
        } ?: return false
        for (entry in alternatives) {
            val type = (entry.getOrNull(0) as? Number)?.toInt() ?: continue
            val value = entry.getOrNull(1)?.toString() ?: continue
            if (type == DNS_NAME && matchesDnsName(identity, value)) return true
            if (type == IP_ADDRESS && sameAddress(identity, value)) return true
        }
        return false
    }

    /** RFC 2818: a wildcard covers exactly one label and never the bare domain. */
    private fun matchesDnsName(identity: String, san: String): Boolean {
        if (!san.startsWith("*.")) return identity.equals(san, ignoreCase = true)
        val suffix = san.substring(1)
        if (!identity.endsWith(suffix, ignoreCase = true) || identity.length <= suffix.length) return false
        return !identity.dropLast(suffix.length).contains('.')
    }

    private fun sameAddress(identity: String, san: String): Boolean {
        if (identity == san) return true
        return try {
            InetAddress.getByName(identity).address.contentEquals(InetAddress.getByName(san).address)
        } catch (_: Exception) {
            false
        }
    }

    private fun sha256(file: File): String =
        MessageDigest.getInstance("SHA-256").digest(file.readBytes()).joinToString("") { "%02x".format(it) }

    private fun fixtureDirectory(): File {
        val candidates = listOf(
            File("app/src/test/resources/tls/upstream-trust"),
            File("src/test/resources/tls/upstream-trust")
        )
        return candidates.firstOrNull { it.isDirectory }
            ?: error("TLS-204 fixture directory missing; run native_build/verification/tls/generate_upstream_trust_fixture.py")
    }

    private fun success(text: String): JSONObject = JSONObject(text).also {
        assertTrue("response too long for the JNI trampoline: ${text.length}", text.length <= MAX_ENVELOPE)
        assertEquals(1, it.getInt("schemaVersion"))
        assertTrue(text, it.getBoolean("success"))
        assertTrue(text, it.isNull("errorCode"))
        assertTrue(text, it.isNull("error"))
    }

    private fun failure(text: String, expected: String): JSONObject = JSONObject(text).also {
        assertTrue("response too long for the JNI trampoline: ${text.length}", text.length <= MAX_ENVELOPE)
        assertEquals(1, it.getInt("schemaVersion"))
        assertFalse(text, it.getBoolean("success"))
        assertEquals(expected, it.getString("errorCode"))
        assertFalse("failure must carry a fixed, non-platform message", it.isNull("error"))
    }

    private companion object {
        const val DNS_NAME = 2
        const val IP_ADDRESS = 7

        /** The serverAuth extended key usage OID a server leaf must carry. */
        const val SERVER_AUTH = "1.3.6.1.5.5.7.3.1"

        /** readJson() in TlsProxyAdapter.cpp refuses a longer verify response. */
        const val MAX_ENVELOPE = 1024
    }
}
