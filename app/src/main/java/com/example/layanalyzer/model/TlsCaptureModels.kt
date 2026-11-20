// Copyright (c) 2026 cheig
// LayerAnalyzer - https://github.com/cheig/LayerAnalyzer
// Licensed under GNU GPL version 3; see LICENSE.

package com.example.layanalyzer.model

import java.net.IDN
import java.util.Locale
import org.json.JSONArray
import org.json.JSONException
import org.json.JSONObject
import org.json.JSONTokener

enum class TlsHostScope(val wireName: String) {
    ExplicitHosts("ExplicitHosts"),
    SelectedApplicationsCandidates("SelectedApplicationsCandidates");

    companion object {
        fun fromWire(value: String): TlsHostScope? = entries.firstOrNull { it.wireName == value }
    }
}

enum class QuicPolicy(val wireName: String) {
    Preserve("Preserve"),
    BlockSelectedUdp443("BlockSelectedUdp443");

    companion object {
        fun fromWire(value: String): QuicPolicy? = entries.firstOrNull { it.wireName == value }
    }
}

/**
 * The destination port [QuicPolicy.BlockSelectedUdp443] intervenes on (design
 * §10.1). One constant, so the rule the settings validate, the rule the
 * forwarding layer applies and the rule the report names cannot drift apart.
 */
const val QUIC_UDP_PORT = 443

data class TlsCaptureSettings(
    val enabled: Boolean = false,
    val candidatePorts: Set<Int> = setOf(443),
    val hostScope: TlsHostScope = TlsHostScope.ExplicitHosts,
    val includeHosts: List<String> = emptyList(),
    val bypassHosts: List<String> = emptyList(),
    val quicPolicy: QuicPolicy = QuicPolicy.Preserve,
    val retainSecrets: Boolean = true
)

enum class TlsSettingsIssueCode(val wireName: String, val displayReason: String) {
    INVALID_JSON("INVALID_JSON", "TLS settings could not be read; TLS is disabled."),
    INVALID_TYPE("INVALID_TYPE", "A TLS setting has an invalid type; TLS is disabled."),
    UNKNOWN_ENUM("UNKNOWN_ENUM", "A TLS setting is not supported; TLS is disabled."),
    UNSUPPORTED_VERSION("UNSUPPORTED_VERSION", "This TLS settings version is not supported; TLS is disabled."),
    INVALID_PORT("INVALID_PORT", "TLS candidate ports must be between 1 and 65535."),
    APPLICATION_SCOPE_REQUIRED("APPLICATION_SCOPE_REQUIRED", "Select at least one VPN application for this TLS scope."),
    INVALID_HOST_RULE("INVALID_HOST_RULE", "Use an exact domain, a *.domain subdomain rule, or an exact IP address."),

    /**
     * TLS-314: blocking UDP/443 is a destination-port rule applied at the
     * forwarding layer, where there is no UID and no SNI. It can therefore only
     * be expressed for a scope that is uniform over the selected applications'
     * destinations — every candidate host, with no explicit bypass — and only
     * when port 443 is still a TCP candidate to fall back to. Any narrower or
     * partial scope would be over-blocking something the user did not select.
     */
    QUIC_SCOPE_UNDECIDABLE(
        "QUIC_SCOPE_UNDECIDABLE",
        "UDP/443 can only be blocked for the selected-applications scope with no bypass rules " +
            "and port 443 among the candidate ports."
    )
}

/** Field names and indices are safe to display; the rejected input is never included. */
data class TlsSettingsIssue(
    val code: TlsSettingsIssueCode,
    val field: String,
    val index: Int? = null
) {
    val displayReason: String get() = code.displayReason
}

data class TlsSettingsValidation(
    val settings: TlsCaptureSettings,
    val issues: List<TlsSettingsIssue> = emptyList()
) {
    val isValid: Boolean get() = issues.isEmpty()
}

/** Input representation only. Routing and bypass precedence belong to TLS-208. */
sealed class TlsHostRule {
    abstract val normalized: String

    data class ExactDomain(override val normalized: String) : TlsHostRule()
    data class Subdomains(val domain: String) : TlsHostRule() {
        override val normalized: String get() = "*.$domain"
    }
    data class ExactIp(override val normalized: String) : TlsHostRule()

    companion object {
        /** No DNS lookup, regex rules, ports, scoped IPs or URL syntax are accepted. */
        fun parse(input: String): TlsHostRule? {
            if (input.isEmpty() || input.any { it.isWhitespace() || it.isISOControl() }) return null
            if (input.any { it in "/\\[]%@?#" }) return null
            val subdomains = input.startsWith("*.")
            val value = if (subdomains) input.substring(2) else input
            if ('*' in value) return null
            if (':' in value) {
                if (subdomains) return null
                return normalizeIpv6(value)?.let(::ExactIp)
            }
            val ascii = try {
                IDN.toASCII(value, IDN.USE_STD3_ASCII_RULES).lowercase(Locale.ROOT).removeSuffix(".")
            } catch (_: IllegalArgumentException) {
                return null
            }
            if (ascii.isEmpty() || ascii.length > 253 || ascii.split('.').any { it.isEmpty() || it.length > 63 }) {
                return null
            }
            if (ascii.all { it in '0'..'9' || it == '.' }) {
                // Do not turn an invalid/ambiguous numeric IP into a DNS suffix rule.
                if (subdomains || input.endsWith('.') || !validIpv4(ascii)) return null
                return ExactIp(ascii)
            }
            return if (subdomains) Subdomains(ascii) else ExactDomain(ascii)
        }

        private fun validIpv4(value: String): Boolean {
            val parts = value.split('.')
            return parts.size == 4 && parts.all {
                it.isNotEmpty() && it.all { char -> char in '0'..'9' } &&
                    (it.length == 1 || it[0] != '0') && (it.toIntOrNull() ?: -1) in 0..255
            }
        }

        private fun normalizeIpv6(value: String): String? {
            var address = value
            if ('.' in address) {
                val ipv4 = address.substringAfterLast(':')
                if (!validIpv4(ipv4)) return null
                val octets = ipv4.split('.').map { it.toInt() }
                address = address.substringBeforeLast(':') + ":" +
                    ((octets[0] shl 8) or octets[1]).toString(16) + ":" +
                    ((octets[2] shl 8) or octets[3]).toString(16)
            }
            if (address.any { it !in "0123456789abcdefABCDEF:" }) return null
            val halves = address.split("::")
            if (halves.size > 2) return null
            fun groups(part: String): List<String> = if (part.isEmpty()) emptyList() else part.split(':')
            val left = groups(halves[0])
            val right = if (halves.size == 2) groups(halves[1]) else emptyList()
            val explicit = left + right
            if (explicit.any { it.isEmpty() || it.length > 4 }) return null
            val missing = 8 - explicit.size
            if (if (halves.size == 2) missing < 1 else missing != 0) return null
            val expanded = left + List(missing) { "0" } + right
            return expanded.joinToString(":") { it.toInt(16).toString(16) }
        }
    }
}

object TlsCaptureSettingsValidator {
    /** allowedApplications is the VPN package allowlist, never UIDs or SOCKS source ports. */
    fun validate(
        settings: TlsCaptureSettings,
        allowedApplications: Collection<String> = emptyList()
    ): TlsSettingsValidation {
        val issues = mutableListOf<TlsSettingsIssue>()
        if (settings.candidatePorts.any { it !in 1..65535 }) {
            issues += TlsSettingsIssue(TlsSettingsIssueCode.INVALID_PORT, "candidatePorts")
        }
        if (settings.hostScope == TlsHostScope.SelectedApplicationsCandidates &&
            allowedApplications.none { it.isNotBlank() }
        ) {
            issues += TlsSettingsIssue(TlsSettingsIssueCode.APPLICATION_SCOPE_REQUIRED, "hostScope")
        }
        // TLS-314: UDP/443 can only be intervened on by destination port, so the
        // mode is refused whenever the interception scope is not exactly "every
        // destination of the selected applications" — an explicit-host scope, any
        // bypass rule (C04: an explicit bypass always wins) or a candidate list
        // without port 443 (there would be no TCP connection to fall back to).
        // Refusing is deliberate: the alternative is dropping datagrams outside
        // the scope the user declared, and the switch is rendered off when the
        // configuration is invalid (no silent narrowing to Preserve). Gating on
        // `enabled` keeps a remembered-but-inactive choice intact: with TLS off
        // no UDP rule is ever applied, so the document must still round-trip.
        if (settings.enabled && settings.quicPolicy == QuicPolicy.BlockSelectedUdp443) {
            val uniformScope = settings.hostScope == TlsHostScope.SelectedApplicationsCandidates &&
                allowedApplications.any { it.isNotBlank() }
            if (!uniformScope || settings.bypassHosts.isNotEmpty() || QUIC_UDP_PORT !in settings.candidatePorts) {
                issues += TlsSettingsIssue(TlsSettingsIssueCode.QUIC_SCOPE_UNDECIDABLE, "quicPolicy")
            }
        }
        fun normalize(rules: List<String>, field: String): List<String> = rules.mapIndexedNotNull { index, rule ->
            val parsed = TlsHostRule.parse(rule)
            if (parsed == null) issues += TlsSettingsIssue(TlsSettingsIssueCode.INVALID_HOST_RULE, field, index)
            parsed?.normalized
        }.distinct()
        val includes = normalize(settings.includeHosts, "includeHosts")
        val bypasses = normalize(settings.bypassHosts, "bypassHosts")
        return TlsSettingsValidation(
            // No partial recovery: dropping an invalid bypass rule could broaden interception.
            settings = if (issues.isEmpty()) settings.copy(
                candidatePorts = settings.candidatePorts.toSet(), includeHosts = includes, bypassHosts = bypasses
            ) else TlsCaptureSettings(),
            issues = issues
        )
    }
}

/** Pure JSON boundary; storage and LiveCaptureSettings integration are owned by TLS-304. */
object TlsCaptureSettingsJson {
    fun encode(settings: TlsCaptureSettings): String = JSONObject()
        .put("schemaVersion", 1)
        .put("enabled", settings.enabled)
        .put("candidatePorts", JSONArray(settings.candidatePorts.sorted()))
        .put("hostScope", settings.hostScope.wireName)
        .put("includeHosts", JSONArray(settings.includeHosts))
        .put("bypassHosts", JSONArray(settings.bypassHosts))
        .put("quicPolicy", settings.quicPolicy.wireName)
        .put("retainSecrets", settings.retainSecrets)
        .toString()

    fun decode(json: String?, allowedApplications: Collection<String> = emptyList()): TlsSettingsValidation {
        if (json == null) return TlsSettingsValidation(TlsCaptureSettings())
        return readSafely { read(readObject(json), allowedApplications) }
    }

    /** The containing settings object stores TLS under "tls"; legacy objects lack this key. */
    fun decodeCaptureSettings(json: String, allowedApplications: Collection<String> = emptyList()): TlsSettingsValidation =
        readSafely {
            val root = readObject(json)
            if (!root.has("tls")) TlsSettingsValidation(TlsCaptureSettings())
            else read(root.opt("tls") as? JSONObject ?: invalidType("tls"), allowedApplications)
        }

    private fun readObject(json: String): JSONObject {
        val tokens = JSONTokener(json)
        val root = tokens.nextValue()
        if (root !is JSONObject || tokens.nextClean() != '\u0000') throw JSONException("Invalid TLS settings JSON")
        return root
    }

    private fun read(json: JSONObject, allowedApplications: Collection<String>): TlsSettingsValidation {
        fun boolean(field: String, default: Boolean): Boolean =
            if (!json.has(field)) default else json.opt(field) as? Boolean ?: invalidType(field)
        fun string(field: String, default: String): String =
            if (!json.has(field)) default else json.opt(field) as? String ?: invalidType(field)
        fun array(field: String): JSONArray? =
            if (!json.has(field)) null else json.opt(field) as? JSONArray ?: invalidType(field)
        fun strings(field: String): List<String> {
            val values = array(field) ?: return emptyList()
            return (0 until values.length()).map { values.opt(it) as? String ?: invalidType(field) }
        }
        if (json.has("schemaVersion") && json.opt("schemaVersion") != 1) {
            throw InvalidSettings(TlsSettingsIssue(TlsSettingsIssueCode.UNSUPPORTED_VERSION, "schemaVersion"))
        }
        val hostScope = TlsHostScope.fromWire(string("hostScope", TlsHostScope.ExplicitHosts.wireName))
            ?: throw InvalidSettings(TlsSettingsIssue(TlsSettingsIssueCode.UNKNOWN_ENUM, "hostScope"))
        val quicPolicy = QuicPolicy.fromWire(string("quicPolicy", QuicPolicy.Preserve.wireName))
            ?: throw InvalidSettings(TlsSettingsIssue(TlsSettingsIssueCode.UNKNOWN_ENUM, "quicPolicy"))
        val ports = array("candidatePorts")?.let { values ->
            (0 until values.length()).map {
                // Reject strings, decimals, null and overflow rather than coercing them.
                values.opt(it) as? Int ?: invalidType("candidatePorts")
            }.toSet()
        } ?: setOf(443)
        return TlsCaptureSettingsValidator.validate(
            TlsCaptureSettings(
                enabled = boolean("enabled", false), candidatePorts = ports, hostScope = hostScope,
                includeHosts = strings("includeHosts"), bypassHosts = strings("bypassHosts"),
                quicPolicy = quicPolicy, retainSecrets = boolean("retainSecrets", true)
            ), allowedApplications
        )
    }

    private fun readSafely(block: () -> TlsSettingsValidation): TlsSettingsValidation = try {
        block()
    } catch (failure: InvalidSettings) {
        TlsSettingsValidation(TlsCaptureSettings(), listOf(failure.issue))
    } catch (_: JSONException) {
        TlsSettingsValidation(TlsCaptureSettings(), listOf(TlsSettingsIssue(TlsSettingsIssueCode.INVALID_JSON, "tls")))
    }

    private fun invalidType(field: String): Nothing =
        throw InvalidSettings(TlsSettingsIssue(TlsSettingsIssueCode.INVALID_TYPE, field))

    private class InvalidSettings(val issue: TlsSettingsIssue) : IllegalArgumentException(issue.code.wireName)
}

enum class TlsErrorCode(val wireName: String) {
    INVALID_ARGUMENT("INVALID_ARGUMENT"), NOT_READY("NOT_READY"), UNSUPPORTED("UNSUPPORTED"),
    STALE_GENERATION("STALE_GENERATION"), CANCELLED("CANCELLED"), IO_ERROR("IO_ERROR"),
    CAPACITY_EXCEEDED("CAPACITY_EXCEEDED"), PROTECT_FAILED("PROTECT_FAILED"), NETWORK_CHANGED("NETWORK_CHANGED"),
    UPSTREAM_CERT_INVALID("UPSTREAM_CERT_INVALID"), DOWNSTREAM_TLS_REJECTED("DOWNSTREAM_TLS_REJECTED"),
    SECRETS_INCOMPLETE("SECRETS_INCOMPLETE"), CAPTURE_CONTEXT_MISSING("CAPTURE_CONTEXT_MISSING"),
    KEY_UNAVAILABLE("KEY_UNAVAILABLE"), UNKNOWN("UNKNOWN");

    companion object {
        fun fromWire(value: String?): TlsErrorCode = entries.firstOrNull { it.wireName == value } ?: UNKNOWN
    }
}

/** Only a sanitized description may cross this boundary; no keylog, private key or plaintext. */
data class TlsError(val code: TlsErrorCode, val safeDescription: String? = null)

enum class TlsConnectionPhase(val wireName: String, val isTerminal: Boolean = false) {
    ACCEPTED("ACCEPTED"), SNIFFING("SNIFFING"), UPSTREAM_HANDSHAKE("UPSTREAM_HANDSHAKE"),
    DOWNSTREAM_HANDSHAKE("DOWNSTREAM_HANDSHAKE"), RELAYING("RELAYING"), PASSTHROUGH("PASSTHROUGH"),
    CLOSED("CLOSED", true), FAILED("FAILED", true), UNKNOWN("UNKNOWN");

    companion object {
        fun fromWire(value: String?): TlsConnectionPhase = entries.firstOrNull { it.wireName == value } ?: UNKNOWN
    }
}

enum class TlsCaptureStatus(val wireName: String) {
    DISABLED("DISABLED"), STARTING("STARTING"), RUNNING("RUNNING"), PAUSED("PAUSED"),
    FAILED("FAILED"), UNSUPPORTED("UNSUPPORTED"), STOPPED("STOPPED"), UNKNOWN("UNKNOWN");

    companion object {
        fun fromWire(value: String?): TlsCaptureStatus = entries.firstOrNull { it.wireName == value } ?: UNKNOWN
    }
}

/** Metadata only. TLS-212 owns sequencing and the publish-once terminal state machine. */
data class TlsConnectionEvent(
    val captureId: String,
    val connectionId: String,
    val eventSequence: Long,
    val monotonicNanos: Long,
    val wallTimeMillis: Long,
    val destinationIp: String,
    val destinationPort: Int,
    val networkGeneration: Long,
    val phase: TlsConnectionPhase = TlsConnectionPhase.ACCEPTED,
    val sni: String? = null,
    val downstreamClientRandom: String? = null,
    val downstreamTls: String? = null,
    val upstreamTls: String? = null,
    val alpn: String? = null,
    val decisionReason: String? = null,
    val error: TlsError? = null,
    val upstreamCertificateSha256: String? = null,
    val secretRecordsAccepted: Long = 0,
    val secretRecordsPersisted: Long = 0,
    val secretsComplete: Boolean = false
)

/** These revisions belong to analysis, not to a network or encrypted-record sequence. */
data class TlsAnalysisGeneration(
    val captureId: String,
    val secretsGeneration: Long = 0,
    val dissectionGeneration: Long = 0
)

/** Independent measured counts: proxy, persistence and Wireshark plaintext are not interchangeable. */
data class TlsCaptureStats(
    val status: TlsCaptureStatus = TlsCaptureStatus.DISABLED,
    val acceptedConnections: Long = 0,
    val proxiedConnections: Long = 0,
    val secretsSavedConnections: Long = 0,
    val decryptedConnections: Long = 0,
    val passthroughConnections: Long = 0,
    val failedConnections: Long = 0,
    val quicUndecryptedConnections: Long = 0,
    val secretRecordsAccepted: Long = 0,
    val secretRecordsPersisted: Long = 0
)
