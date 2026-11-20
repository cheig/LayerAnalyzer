package com.example.layanalyzer.capture.tls

import android.net.http.X509TrustManagerExtensions
import org.json.JSONObject
import java.io.ByteArrayInputStream
import java.net.InetAddress
import java.security.KeyStore
import java.security.cert.CertificateException
import java.security.cert.CertificateFactory
import java.security.cert.CertificateParsingException
import java.security.cert.X509Certificate
import javax.net.ssl.TrustManagerFactory
import javax.net.ssl.X509TrustManager

/**
 * The chain-and-name half of the C05 platform boundary (TLS-204): given the
 * peer chain of an upstream TLS handshake, the reference identity and the
 * negotiated algorithms, decide whether that upstream may be trusted.
 *
 * The production delegate is the device's own trust store. A fixture delegate
 * with test-only roots is injected by tests and never by production code.
 *
 * Implementations must reject rather than degrade: returning normally means
 * "chain and identity are verified"; anything else must throw.
 */
fun interface UpstreamChainVerifier {
    /**
     * @throws CertificateException when the chain or the identity is not trusted
     * @throws PlatformTrustUnavailableException when the platform cannot perform
     *   an audited chain-plus-name verification at all
     */
    @Throws(CertificateException::class)
    fun verify(chain: Array<X509Certificate>, authType: String, identity: String)
}

/**
 * The platform has no reviewable `X509TrustManagerExtensions`. This is a
 * capability gap, not a certificate verdict, so it is reported as UNSUPPORTED
 * and never as a successful verification or as an upstream rejection.
 */
class PlatformTrustUnavailableException(message: String) : IllegalStateException(message)

/**
 * Production upstream verification (TLS-204). Installed once per capture as the
 * `verifyUpstream` method of the assembled [TlsPlatformCallbacks] composite
 * (TLS-216), and called from Go's mandatory `VerifyConnection` on a Go worker
 * thread.
 *
 * Name verification is done independently by every layer, because no single one
 * of them is allowed to be the only check:
 *
 *  - Go's `VerifyConnection` proves the leaf against the reference identity
 *    before this callback is ever entered;
 *  - this class re-derives the RFC 6125 DNS/IP decision from the leaf's SANs
 *    itself and rejects a mismatch before the delegate is consulted. It has to:
 *    on device the platform's hostname-taking overload ignores the `host`
 *    argument, so a chain-only platform answer would otherwise be mistaken for a
 *    verified identity;
 *  - the device's trust store is still asked to validate the chain (and the
 *    name) through the hostname-taking overload, so the platform chain check is
 *    never skipped either.
 *
 * The hostname-less overload is never used. Nothing here logs, stores or returns
 * certificate material, an identity, or platform exception text.
 */
class AndroidUpstreamTrustVerifier(
    private val delegate: UpstreamChainVerifier = AndroidSystemTrustManager()
) {
    /**
     * Returns the C05 `schemaVersion:1` envelope. The JNI trampoline reads only
     * `errorCode` and refuses a response longer than 1024 bytes, so failures
     * carry a fixed message and never serialise the platform's own exception.
     */
    fun verifyUpstream(chainDer: Array<ByteArray>, identity: String, authType: String, tlsVersion: String): String {
        val certificates = UpstreamTrustInput.certificates(chainDer)
            ?: return UpstreamTrustInput.failure("INVALID_ARGUMENT", "Certificate chain rejected")
        val reference = UpstreamTrustInput.identity(identity)
            ?: return UpstreamTrustInput.failure("INVALID_ARGUMENT", "Reference identity rejected")
        if (tlsVersion !in UpstreamTrustInput.supportedVersions) {
            return UpstreamTrustInput.failure("UNSUPPORTED", "Negotiated protocol version not supported")
        }
        val derived = UpstreamTrustInput.authType(certificates[0])
            ?: return UpstreamTrustInput.failure("UNSUPPORTED", "Leaf key algorithm not supported")
        if (derived != UpstreamTrustInput.normalizedAuthType(authType)) {
            // Both halves derive this from the same leaf, so a disagreement means
            // they are not looking at the same chain. Never continue silently.
            return UpstreamTrustInput.failure("INVALID_ARGUMENT", "Reported auth type does not match the leaf")
        }
        // Pre-emptive name check: the platform's hostname-taking overload does
        // not actually check the name on device, so a chain-only pass must never
        // stand in for a proven identity. This rejects early; it does not replace
        // the delegate, which is still asked to validate the chain below.
        if (!UpstreamNameVerifier.matches(reference, certificates[0])) {
            return UpstreamTrustInput.failure(
                "UPSTREAM_CERT_INVALID",
                "Upstream reference identity is not proven by the certificate"
            )
        }
        return try {
            delegate.verify(certificates, derived, reference)
            UpstreamTrustInput.success()
        } catch (_: PlatformTrustUnavailableException) {
            UpstreamTrustInput.failure("UNSUPPORTED", "Platform trust manager unavailable")
        } catch (_: CertificateException) {
            UpstreamTrustInput.failure("UPSTREAM_CERT_INVALID", "Upstream certificate rejected")
        } catch (_: Exception) {
            // Any other platform failure is a failure, never a pass.
            UpstreamTrustInput.failure("IO_ERROR", "Upstream verification failed")
        }
    }
}

/**
 * The production trust source: the device's own X509 trust manager, wrapped in
 * [X509TrustManagerExtensions] so the hostname-checking overload is the only
 * entry point. `init(null)` selects the platform's default trust store - not
 * Go's root pool, and not a copy of roots shipped in the APK - so an upstream is
 * accepted exactly when this device would accept it. Importing a capture CA is
 * never a reason to skip a check here.
 *
 * This is deliberately the *platform* policy, not a reproduction of the
 * intercepted app's own configuration (certificate pinning, a custom
 * `TrustManager`, a network security config that opts out of user-added roots).
 * The difference is recorded in the TLS-204 evidence: it can only make this
 * check stricter than the app's or looser than it, never a way around pinning,
 * because the app still verifies the downstream leaf this proxy presents.
 *
 * The wrapper constructor rejects a trust manager that cannot be audited, so an
 * unusable platform reports UNSUPPORTED instead of a weaker check.
 */
internal class AndroidSystemTrustManager : UpstreamChainVerifier {
    // Resolved once, at construction: a broken or unauditable platform is an
    // UNSUPPORTED capability rather than a per-call surprise, and a plain
    // Exception is caught so that an Error (a broken VM) still propagates.
    private val extensions: Result<X509TrustManagerExtensions> = try {
        val factory = TrustManagerFactory.getInstance("X509")
        factory.init(null as KeyStore?)
        val manager = factory.trustManagers?.filterIsInstance<X509TrustManager>()?.singleOrNull()
            ?: throw PlatformTrustUnavailableException("system trust manager missing")
        Result.success(X509TrustManagerExtensions(manager))
    } catch (error: Exception) {
        // Never re-serialise the platform message; it is dropped here and only a
        // fixed envelope text is returned to the caller.
        Result.failure(PlatformTrustUnavailableException("system trust manager unusable: ${error.javaClass.name}"))
    }

    override fun verify(chain: Array<X509Certificate>, authType: String, identity: String) {
        val manager = extensions.getOrElse {
            throw PlatformTrustUnavailableException("system trust manager unavailable")
        }
        // The hostname-taking overload: chain and identity in one audited call.
        manager.checkServerTrusted(chain, authType, identity)
    }
}

/**
 * Pure input policy of upstream verification (TLS-204). It touches no Android
 * class so the host tests can drive it directly, and it mirrors the Go half
 * exactly: the same 16-certificate and 64 KiB limits the C05 ABI enforces, the
 * same 253-byte ASCII reference identity, and the same key-algorithm names.
 */
internal object UpstreamTrustInput {
    const val MAX_CERTIFICATES = 16
    const val MAX_CERTIFICATE_BYTES = 65_536
    const val MAX_IDENTITY_LENGTH = 253
    const val MAX_LABEL_LENGTH = 63

    /**
     * Supported version matrix, pinned by a host test. Both versions are
     * verified the same way and only by the same mandatory callback:
     *
     * | negotiated | leaf key | authType passed | state |
     * |---|---|---|---|
     * | TLSv1.2 | RSA | `RSA` | supported |
     * | TLSv1.2 | EC | `ECDSA` | supported |
     * | TLSv1.3 | RSA | `RSA` | supported |
     * | TLSv1.3 | EC | `ECDSA` | supported |
     * | TLSv1.2/1.3 | DSA | `DSA` | mapped; no modern upstream uses it |
     * | TLSv1.2/1.3 | Ed25519/EdDSA | `EDDSA` | mapped; platform support is device-unverified (TLS-217) |
     * | TLSv1.0/1.1, SSLv3 | any | - | `UNSUPPORTED`: never intercepted |
     */
    val supportedVersions: Set<String> = setOf("TLSv1.2", "TLSv1.3")

    /**
     * Parses the leaf-first DER chain into certificates, applying the ABI limits
     * before any platform call. `null` means the input is not a usable chain.
     */
    fun certificates(chainDer: Array<ByteArray>): Array<X509Certificate>? {
        if (chainDer.size !in 1..MAX_CERTIFICATES) return null
        val factory = CertificateFactory.getInstance("X.509")
        val parsed = ArrayList<X509Certificate>(chainDer.size)
        for (der in chainDer) {
            if (der.size !in 1..MAX_CERTIFICATE_BYTES) return null
            val certificate = try {
                factory.generateCertificate(ByteArrayInputStream(der)) as? X509Certificate
            } catch (_: Exception) {
                null
            }
            if (certificate == null) return null
            parsed += certificate
        }
        return parsed.toTypedArray()
    }

    /**
     * Canonicalises the reference identity: one trailing dot is removed (the
     * same rule the resolver and the Go half use) and nothing else is rewritten,
     * because IDNA, wildcard and exact-name policy belong to the policy layer
     * (TLS-208). Case is preserved; both matching rules are case-insensitive.
     *
     * Either a bare IP literal or an exact DNS name is accepted. A port, a
     * wildcard, a bracketed literal, a scoped address, a control character or a
     * non-ASCII byte is rejected instead of reinterpreted.
     */
    fun identity(value: String): String? {
        if (value.isEmpty() || value.length > MAX_IDENTITY_LENGTH) return null
        if (value.any { it.code < 0x20 || it.code > 0x7e }) return null
        val name = value.removeSuffix(".")
        if (name.isEmpty() || name.length > MAX_IDENTITY_LENGTH) return null
        if (isIpLiteral(name)) return name
        for (label in name.split('.')) {
            if (label.isEmpty() || label.length > MAX_LABEL_LENGTH) return null
            if (!isAsciiAlphanumeric(label.first()) || !isAsciiAlphanumeric(label.last())) return null
            if (label.any { !isAsciiAlphanumeric(it) && it != '-' && it != '_' }) return null
        }
        return name
    }

    /**
     * The authType passed to the platform, derived from the leaf itself so it
     * always matches the certificate being verified. `null` means this key
     * algorithm is outside the supported matrix.
     */
    fun authType(leaf: X509Certificate): String? = when (leaf.publicKey.algorithm.uppercase()) {
        "RSA" -> "RSA"
        "EC", "ECDSA" -> "ECDSA"
        "DSA" -> "DSA"
        "EDDSA", "ED25519" -> "EDDSA"
        else -> null
    }

    /** JSSE spelling of the authType the Go half reports, or `null` if unknown. */
    fun normalizedAuthType(reported: String): String? = when (reported.uppercase()) {
        "RSA" -> "RSA"
        "EC", "ECDSA" -> "ECDSA"
        "DSA" -> "DSA"
        "EDDSA", "ED25519" -> "EDDSA"
        else -> null
    }

    fun envelope(code: String?, error: String): String = JSONObject()
        .put("schemaVersion", 1)
        .put("success", code == null)
        .put("errorCode", code ?: JSONObject.NULL)
        .put("error", if (code == null) JSONObject.NULL else error)
        .toString()

    fun success(): String = envelope(null, "")

    fun failure(code: String, error: String): String = envelope(code, error)

    /** A scoped address cannot be verified through the ABI, which carries no zone. */
    internal fun isIpLiteral(value: String): Boolean {
        if (value.contains('%')) return false
        // A bracketed literal is not a reference identity: the policy layer
        // produces a bare address, and the Go half rejects brackets as well.
        if (value.contains('[') || value.contains(']')) return false
        if (value.contains(':')) {
            // A colon is never a DNS label character, so this is either an IPv6
            // literal or nothing; `InetAddress` parses it without any lookup.
            return try {
                java.net.InetAddress.getByName(value)
                true
            } catch (_: Exception) {
                false
            }
        }
        val parts = value.split('.')
        if (parts.size != 4) return false
        return parts.all { part ->
            part.isNotEmpty() && part.length <= 3 && part.all { it in '0'..'9' } && part.toInt() <= 255
        }
    }

    private fun isAsciiAlphanumeric(c: Char): Boolean =
        c in 'a'..'z' || c in 'A'..'Z' || c in '0'..'9'
}

/**
 * RFC 6125 reference-identity matching (TLS-204). Pure JVM: it reads only the
 * leaf's `subjectAlternativeNames` and touches no Android class, so the host
 * tests drive it directly. It mirrors the Go half's `leaf.VerifyHostname`:
 *
 *  - a DNS identity matches a `dNSName` SAN case-insensitively. A SAN whose
 *    first label is exactly `*` covers exactly one label and never the bare
 *    name, so `*.a.test` matches `x.a.test` but not `a.test` or `x.y.a.test`;
 *  - an IP identity matches an `iPAddress` SAN by address bytes, not by string
 *    equality, so `::1` and `0:0:0:0:0:0:0:1` are the same address;
 *  - the two families never cross: an IP identity is never matched against DNS
 *    SANs and a DNS identity is never matched against IP SANs;
 *  - a leaf with no SAN, or one whose SAN extension cannot be parsed, matches
 *    nothing (fail closed).
 */
internal object UpstreamNameVerifier {
    const val DNS_NAME = 2
    const val IP_ADDRESS = 7

    /** True when the already-canonicalised [identity] is proven by [leaf]. */
    fun matches(identity: String, leaf: X509Certificate): Boolean {
        val alternatives = try {
            leaf.subjectAlternativeNames
        } catch (_: CertificateParsingException) {
            null
        }
        return matchesAlternatives(identity, alternatives)
    }

    /**
     * The decision itself, over an already-parsed SAN collection. `null` and an
     * empty collection both mean "no SAN", which matches nothing.
     */
    fun matchesAlternatives(identity: String, alternatives: Collection<List<*>>?): Boolean {
        if (alternatives.isNullOrEmpty()) return false
        val identityAddress = if (UpstreamTrustInput.isIpLiteral(identity)) addressBytes(identity) else null
        for (entry in alternatives) {
            val type = (entry.getOrNull(0) as? Number)?.toInt() ?: continue
            val value = entry.getOrNull(1) ?: continue
            if (identityAddress != null) {
                if (type == IP_ADDRESS && sameAddress(identityAddress, value)) return true
            } else if (type == DNS_NAME && value is String && matchesDnsName(identity, value)) {
                return true
            }
        }
        return false
    }

    private fun matchesDnsName(identity: String, san: String): Boolean {
        if (!san.startsWith("*.")) return identity.equals(san, ignoreCase = true)
        val suffix = san.substring(1)
        if (!identity.endsWith(suffix, ignoreCase = true) || identity.length <= suffix.length) return false
        val label = identity.substring(0, identity.length - suffix.length)
        return label.isNotEmpty() && !label.contains('.')
    }

    private fun sameAddress(identity: ByteArray, san: Any): Boolean {
        val sanBytes = when (san) {
            is ByteArray -> san
            is String -> addressBytes(san) ?: return false
            else -> return false
        }
        return identity.contentEquals(sanBytes)
    }

    /** Only ever called with a literal: `identity` is pre-checked, SANs are type 7. */
    private fun addressBytes(literal: String): ByteArray? = try {
        InetAddress.getByName(literal).address
    } catch (_: Exception) {
        null
    }
}
